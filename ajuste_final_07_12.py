import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from scapy.all import sniff, conf, Dot11, RadioTap, Dot11ProbeReq, Dot11ProbeResp, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11Auth, Dot11AssoReq, Dot11AssoResp
import threading
import datetime
import os
import time
from queue import Queue
from collections import defaultdict
import subprocess
import sqlite3
import webbrowser
import json
import random
import re

class NetworkProblemSolver:
    def __init__(self, db_name="wireless_monitor.db"):
        self.db_name = db_name
        self.init_diagnostics_database()
        
        # Base de conhecimento de problemas WiFi - APRIMORADA
        self.problem_knowledge_base = {
            'high_latency': {
                'name': 'Latência Alta',
                'thresholds': {'latency': 100, 'jitter': 30},
                'symptoms': ['latência acima de 100ms', 'jitter alto', 'chamadas com eco'],
                'causes': [
                    'Canal WiFi congestionado',
                    'Muitas redes vizinhas no mesmo canal',
                    'Roteador sobrecarregado',
                    'Interferência de dispositivos 2.4GHz',
                    'QoS não configurado'
                ],
                'solutions': [
                    'Mudar para canal menos utilizado (1, 6 ou 11)',
                    'Ativar QoS no roteador para priorizar tráfego',
                    'Reposicionar roteador longe de interferências',
                    'Reiniciar roteador para limpar cache',
                    'Usar banda 5GHz se disponível'
                ],
                'severity': 'medium'
            },
            'packet_loss': {
                'name': 'Perda de Pacotes',
                'thresholds': {'packet_loss': 5},
                'symptoms': ['downloads interrompidos', 'voz cortando', 'vídeos travando'],
                'causes': [
                    'Sinal WiFi fraco',
                    'Muitas obstruções no caminho',
                    'Interferência de microondas/bluetooth',
                    'Problemas no hardware do roteador',
                    'Driver desatualizado da placa WiFi'
                ],
                'solutions': [
                    'Mover dispositivo mais perto do roteador',
                    'Reduzir obstáculos entre dispositivo e roteador',
                    'Evitar usar microondas durante videoconferências',
                    'Atualizar drivers da placa WiFi',
                    'Considerar repetidor WiFi'
                ],
                'severity': 'high'
            },
            'slow_speed': {
                'name': 'Velocidade Lenta',
                'thresholds': {'throughput': 10},
                'symptoms': ['downloads lentos', 'streaming em baixa qualidade', 'páginas carregando devagar'],
                'causes': [
                    'Canal WiFi muito congestionado',
                    'Dispositivos conectados em banda errada',
                    'Roteador antigo ou limitado',
                    'Plano de internet insuficiente',
                    'Problemas no DNS'
                ],
                'solutions': [
                    'Mudar para canal com menos redes',
                    'Conectar dispositivos críticos via cabo',
                    'Verificar plano de internet contratado',
                    'Usar DNS rápido como Google (8.8.8.8) ou Cloudflare (1.1.1.1)',
                    'Atualizar firmware do roteador'
                ],
                'severity': 'medium'
            },
            'signal_weak': {
                'name': 'Sinal Fraco',
                'thresholds': {'signal_strength': -65},  # MUDADO: de -70 para -65
                'symptoms': ['conexão instável', 'velocidade varia muito', 'desconexões frequentes'],
                'causes': [
                    'Distância muito grande do roteador',
                    'Muitas paredes/obstáculos',
                    'Antenas mal posicionadas',
                    'Roteador em local inadequado',
                    'Interferência de outros dispositivos'
                ],
                'solutions': [
                    'Reposicionar roteador em local central e elevado',
                    'Ajustar ângulo das antenas (vertical para melhor cobertura)',
                    'Remover obstáculos entre dispositivo e roteador',
                    'Considerar sistema mesh ou repetidor',
                    'Usar banda 2.4GHz para maior alcance'
                ],
                'severity': 'high'
            },
            'channel_congestion': {
                'name': 'Canal Congestionado',
                'thresholds': {'nearby_networks': 10},
                'symptoms': ['performance piora em horários de pico', 'interferência intermitente'],
                'causes': [
                    'Muitas redes no mesmo canal',
                    'Canais sobrepostos sendo usados',
                    'Ambiente urbano denso',
                    'Canal automático escolhendo mal'
                ],
                'solutions': [
                    'Mudar para canal 1, 6 ou 11 (não sobrepostos)',
                    'Usar análise de espectro para escolher melhor canal',
                    'Considerar banda 5GHz com mais canais disponíveis',
                    'Configurar canal fixo em vez de automático'
                ],
                'severity': 'medium'
            },
            'non_standard_channel': {
                'name': 'Canal Não-Padrão',
                'thresholds': {},
                'symptoms': ['interferência constante', 'velocidade abaixo do esperado'],
                'causes': [
                    'Roteador configurado em canal sobreposto (2,3,4,5,7,8,9,10,12,13)',
                    'Configuração automática escolhendo canal errado',
                    'Interferência de canais vizinhos'
                ],
                'solutions': [
                    'Mudar para canal 1, 6 ou 11 (não sobrepostos)',
                    'Desativar seleção automática de canal',
                    'Fazer análise de espectro para escolher melhor canal'
                ],
                'severity': 'medium'
            },
            'deauth_attack': {
                'name': 'Ataque Deauthentication',
                'thresholds': {'deauth_packets': 10},
                'symptoms': ['desconexões repentinas', 'não consegue manter conexão', 'WiFi instável'],
                'causes': [
                    'Ataque ativo de deauthentication na rede',
                    'Dispositivo malicioso na rede',
                    'Ferramentas de pentest sendo executadas'
                ],
                'solutions': [
                    'Verificar dispositivos conectados na rede',
                    'Mudar senha do WiFi',
                    'Ativar filtro MAC',
                    'Usar WPA3 se disponível',
                    'Contatar administrador de rede'
                ],
                'severity': 'critical'
            }
        }

    def init_diagnostics_database(self):
        """Cria tabelas para diagnóstico"""
        try:
            conn = sqlite3.connect(self.db_name)
            cur = conn.cursor()
            
            cur.execute("""
            CREATE TABLE IF NOT EXISTS network_diagnostics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                problem_type TEXT,
                problem_name TEXT,
                severity TEXT,
                confidence INTEGER,
                symptoms_detected TEXT,
                causes TEXT,
                solutions TEXT,
                qos_metrics TEXT,
                environment_data TEXT
            )
            """)
            
            cur.execute("""
            CREATE TABLE IF NOT EXISTS diagnostic_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                action_taken TEXT,
                problem_solved TEXT,
                improvement_metrics TEXT,
                before_metrics TEXT,
                after_metrics TEXT
            )
            """)
            
            conn.commit()
            conn.close()
            print("[DIAGNOSTIC] Banco de dados de diagnóstico inicializado")
        except Exception as e:
            print(f"[DIAGNOSTIC-ERRO] Falha ao inicializar DB: {e}")

    def analyze_network_health(self, qos_metrics, wireless_devices, capture_queue, network_stats, current_wifi_info=None):
        """Analisa a saúde da rede e detecta problemas - APRIMORADA"""
        print("\n🔍 ANALISANDO SAÚDE DA REDE...")
        
        problems_detected = []
        
        # Coleta métricas atuais - COM SINAL REAL
        current_metrics = {
            'latency': qos_metrics['latency'],
            'jitter': qos_metrics['jitter'],
            'packet_loss': qos_metrics['packet_loss'],
            'nearby_networks': len([dev for dev in wireless_devices.values() if dev.get('type') == 'AP']),
            'signal_strength': self.get_real_signal_strength(),  # MUDADO: Agora usa função real
            'throughput': self.estimate_throughput(),
            'deauth_packets': network_stats.get('deauth_count', 0),
            'auth_packets': network_stats.get('auth_count', 0),
            'data_packets': network_stats.get('data_count', 0)
        }
        
        # Adiciona informações da WiFi conectada se disponível
        if current_wifi_info:
            current_metrics.update({
                'connected_ssid': current_wifi_info.get('ssid', 'Desconhecido'),
                'connected_channel': current_wifi_info.get('channel', 0),
                'connected_frequency': current_wifi_info.get('frequency', '2.4GHz'),
                'connected_security': current_wifi_info.get('security', 'Desconhecido')
            })
            
            # Detecção especial para canal não-padrão
            if self._detect_non_standard_channel(current_wifi_info.get('channel', 0)):
                problem_data = self._generate_non_standard_channel_report(current_wifi_info.get('channel', 0))
                problems_detected.append(problem_data)
                capture_queue.put(f"⚠️  PROBLEMA DETECTADO: {problem_data['problem_name']}\n")
                capture_queue.put(f"   Severidade: {problem_data['severity'].upper()}\n")
                capture_queue.put(f"   Confiança: {problem_data['confidence']}%\n")
        
        # Verifica cada tipo de problema
        for problem_id, problem_info in self.problem_knowledge_base.items():
            if problem_id == 'non_standard_channel':
                continue  # Já verificamos acima
                
            if self._detect_problem(problem_id, current_metrics):
                problem_data = self._generate_problem_report(problem_id, current_metrics)
                problems_detected.append(problem_data)
                
                # Adiciona ao log
                capture_queue.put(f"⚠️  PROBLEMA DETECTADO: {problem_data['problem_name']}\n")
                capture_queue.put(f"   Severidade: {problem_data['severity'].upper()}\n")
                capture_queue.put(f"   Confiança: {problem_data['confidence']}%\n")
        
        if problems_detected:
            self._save_diagnosis(problems_detected, current_metrics)
            return problems_detected
        else:
            # Verifica se há canal não-padrão mesmo sem outros problemas
            if current_wifi_info and self._detect_non_standard_channel(current_wifi_info.get('channel', 0)):
                problem_data = self._generate_non_standard_channel_report(current_wifi_info.get('channel', 0))
                problems_detected.append(problem_data)
                self._save_diagnosis(problems_detected, current_metrics)
                return problems_detected
            else:
                capture_queue.put("✅ Rede saudável - nenhum problema crítico detectado\n")
                return []

    def get_real_signal_strength(self):
        """Obtém a força REAL do sinal da rede WiFi conectada"""
        try:
            # Usa iwconfig para obter sinal real
            result = subprocess.run(
                ['iwconfig'], 
                capture_output=True, 
                text=True
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Signal level=' in line:
                        # Extrai valor do sinal em dBm
                        match = re.search(r'Signal level=(-?\d+) dBm', line)
                        if match:
                            return int(match.group(1))
                        # Tenta outros formatos
                        match = re.search(r'Signal level=(-?\d+)/(\d+)', line)
                        if match:
                            # Converte de fração para dBm aproximado
                            signal = int(match.group(1))
                            max_signal = int(match.group(2))
                            # Aproximação: 100% = -20dBm, 0% = -100dBm
                            dbm = -20 + (signal/max_signal * -80)
                            return int(dbm)
            
            # Fallback: tenta obter via iw
            result = subprocess.run(
                ['iw', 'dev', 'wlan0', 'link'],  # Ajuste a interface se necessário
                capture_output=True, 
                text=True
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'signal:' in line:
                        match = re.search(r'signal:\s*(-?\d+)', line)
                        if match:
                            return int(match.group(1))
        
        except Exception as e:
            print(f"[DIAGNOSTIC-ERRO] Falha ao obter sinal: {e}")
        
        # Fallback: retorna um valor razoável
        return -65

    def _detect_problem(self, problem_id, metrics):
        """Detecta se um problema específico está ocorrendo"""
        thresholds = self.problem_knowledge_base[problem_id]['thresholds']
        
        if problem_id == 'high_latency':
            return metrics['latency'] > thresholds['latency'] or metrics['jitter'] > thresholds['jitter']
        
        elif problem_id == 'packet_loss':
            return metrics['packet_loss'] > thresholds['packet_loss']
        
        elif problem_id == 'slow_speed':
            return metrics['throughput'] < thresholds['throughput']
        
        elif problem_id == 'signal_weak':
            return metrics['signal_strength'] < thresholds['signal_strength']
        
        elif problem_id == 'channel_congestion':
            return metrics['nearby_networks'] > thresholds['nearby_networks']
        
        elif problem_id == 'deauth_attack':
            return metrics['deauth_packets'] > thresholds['deauth_packets']
        
        return False

    def _detect_non_standard_channel(self, channel):
        """Detecta se o canal é não-padrão (sobreposto)"""
        if not channel or channel == 0:
            return False
        
        # Para banda 2.4GHz
        if 1 <= channel <= 13:
            # Canais não sobrepostos: 1, 6, 11
            if channel not in [1, 6, 11]:
                return True
        
        return False

    def _generate_non_standard_channel_report(self, channel):
        """Gera relatório para canal não-padrão"""
        problem_info = self.problem_knowledge_base['non_standard_channel']
        
        return {
            'problem_type': 'non_standard_channel',
            'problem_name': f"Canal Não-Padrão ({channel})",
            'severity': problem_info['severity'],
            'confidence': 95,  # Alta confiança para canal detectado
            'symptoms_detected': problem_info['symptoms'],
            'causes': problem_info['causes'],
            'solutions': problem_info['solutions'],
            'metrics': {'channel': channel},
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    def _generate_problem_report(self, problem_id, metrics):
        """Gera relatório detalhado do problema"""
        problem_info = self.problem_knowledge_base[problem_id]
        
        # Calcula confiança baseada na gravidade
        confidence = self._calculate_confidence(problem_id, metrics)
        
        return {
            'problem_type': problem_id,
            'problem_name': problem_info['name'],
            'severity': problem_info['severity'],
            'confidence': confidence,
            'symptoms_detected': problem_info['symptoms'],
            'causes': problem_info['causes'],
            'solutions': problem_info['solutions'],
            'metrics': metrics,
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    def _calculate_confidence(self, problem_id, metrics):
        """Calcula confiança na detecção do problema"""
        base_confidence = 80
        
        if problem_id == 'high_latency':
            if metrics['latency'] > 150:
                base_confidence += 15
            if metrics['jitter'] > 50:
                base_confidence += 10
                
        elif problem_id == 'packet_loss':
            if metrics['packet_loss'] > 10:
                base_confidence += 20
                
        elif problem_id == 'signal_weak':
            if metrics['signal_strength'] < -75:
                base_confidence += 15
            if metrics['signal_strength'] < -80:
                base_confidence += 10
                
        elif problem_id == 'channel_congestion':
            if metrics['nearby_networks'] > 15:
                base_confidence += 15
                
        elif problem_id == 'deauth_attack':
            if metrics['deauth_packets'] > 20:
                base_confidence += 25
                
        return min(base_confidence, 100)

    def estimate_throughput(self):
        """Estima throughput baseado em métricas (simulação)"""
        # Em um sistema real, você mediria isso com iperf ou similar
        return 25  # Mbps

    def _save_diagnosis(self, problems, metrics):
        """Salva diagnóstico no banco de dados"""
        try:
            conn = sqlite3.connect(self.db_name)
            cur = conn.cursor()
            
            for problem in problems:
                cur.execute("""
                    INSERT INTO network_diagnostics 
                    (timestamp, problem_type, problem_name, severity, confidence, symptoms_detected, causes, solutions, qos_metrics, environment_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    problem['timestamp'],
                    problem['problem_type'],
                    problem['problem_name'],
                    problem['severity'],
                    problem['confidence'],
                    '; '.join(problem['symptoms_detected']),
                    '; '.join(problem['causes']),
                    '; '.join(problem['solutions']),
                    str(metrics),
                    str(problem['metrics'])
                ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DIAGNOSTIC-ERRO] Falha ao salvar diagnóstico: {e}")

    def generate_detailed_report(self, problems_detected, wifi_info=None):
        """Gera relatório detalhado para exibição - APRIMORADO"""
        if not problems_detected:
            report = "✅ SUA REDE ESTÁ SAUDÁVEL!\n\nNenhum problema crítico detectado."
            
            # Adiciona informação sobre canal mesmo se não houver problemas
            if wifi_info and wifi_info.get('channel'):
                channel = wifi_info.get('channel')
                signal = wifi_info.get('signal_strength', 'N/A')
                
                report += f"\n\n📊 ESTADO ATUAL:\n"
                report += f"   📶 Sinal: {signal}\n"
                report += f"   📡 Canal: {channel}\n"
                
                if self._detect_non_standard_channel(channel):
                    report += f"   ⚠️  ALERTA: Canal {channel} não é recomendado!\n"
                    report += f"      Use canal 1, 6 ou 11 para melhor performance\n"
                elif channel in [1, 6, 11]:
                    report += f"   ✅ Canal {channel} é ideal (não sobreposto)\n"
                
                # Adiciona recomendação baseada no sinal
                if signal and isinstance(signal, str) and 'dBm' in signal:
                    try:
                        dbm = int(re.search(r'(-?\d+)', signal).group(1))
                        if dbm < -70:
                            report += f"   ⚠️  Sinal fraco ({dbm}dBm)\n"
                            report += f"      Considere aproximar-se do roteador\n"
                    except:
                        pass
            
            return report
        
        report = "📊 RELATÓRIO DE DIAGNÓSTICO DA REDE\n\n"
        report += f"📅 Data: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}\n"
        
        if wifi_info:
            report += f"📶 Conectado a: {wifi_info.get('ssid', 'Desconhecido')}\n"
            report += f"📡 Canal: {wifi_info.get('channel', 'N/A')} | "
            report += f"📶 Sinal: {wifi_info.get('signal_strength', 'N/A')}\n"
        
        report += f"🔍 Problemas detectados: {len(problems_detected)}\n\n"
        
        for i, problem in enumerate(problems_detected, 1):
            report += f"🚨 PROBLEMA {i}: {problem['problem_name']}\n"
            report += f"   ⚠️  Severidade: {problem['severity'].upper()}\n"
            report += f"   🎯 Confiança: {problem['confidence']}%\n\n"
            
            report += f"   📋 SINTOMAS:\n"
            for symptom in problem['symptoms_detected'][:3]:
                report += f"      • {symptom}\n"
            
            report += f"\n   🔍 CAUSAS PROVÁVEIS:\n"
            for cause in problem['causes'][:3]:
                report += f"      • {cause}\n"
            
            report += f"\n   💡 SOLUÇÕES RECOMENDADAS:\n"
            for solution in problem['solutions'][:3]:
                report += f"      • {solution}\n"
            
            report += f"\n   📈 MÉTRICAS:\n"
            if 'signal_strength' in problem['metrics']:
                signal = problem['metrics']['signal_strength']
                report += f"      • Sinal: {signal}dBm\n"
                if signal < -70:
                    report += f"      ⚠️  SINAL FRACO (abaixo de -70dBm)\n"
            
            if 'latency' in problem['metrics']:
                report += f"      • Latência: {problem['metrics']['latency']}ms\n"
            if 'jitter' in problem['metrics']:
                report += f"      • Jitter: {problem['metrics']['jitter']}ms\n"
            if 'packet_loss' in problem['metrics']:
                report += f"      • Perda: {problem['metrics']['packet_loss']}%\n"
            if 'nearby_networks' in problem['metrics']:
                report += f"      • Redes próximas: {problem['metrics']['nearby_networks']}\n"
            if 'channel' in problem['metrics']:
                channel = problem['metrics']['channel']
                report += f"      • Canal: {channel}\n"
                if self._detect_non_standard_channel(channel):
                    report += f"      ⚠️  CANAL NÃO-PADRÃO (sobreposto)\n"
            
            report += "\n" + "─" * 50 + "\n\n"
        
        return report

    def get_quick_fixes(self, problems_detected):
        """Retorna soluções rápidas para problemas detectados"""
        if not problems_detected:
            return ["✅ Sua rede está funcionando bem!"]
        
        quick_fixes = []
        for problem in problems_detected:
            if problem['severity'] in ['high', 'critical']:
                quick_fixes.extend(problem['solutions'][:2])
        
        return list(set(quick_fixes))[:5]  # Remove duplicatas e limita a 5

    def get_recommended_channel(self, wireless_devices, current_channel=None):
        """Recomenda o melhor canal baseado nas redes vizinhas - APRIMORADA"""
        aps = [dev for dev in wireless_devices.values() if dev.get('type') == 'AP']
        channel_count = {}
        
        for ap in aps:
            channel = ap.get('channel')
            if channel:
                # Converte canais não-padrão para o mais próximo padrão (1,6,11)
                if channel in [1, 2, 3, 4, 5]:
                    standardized_channel = 1
                elif channel in [6, 7, 8, 9, 10]:
                    standardized_channel = 6
                elif channel in [11, 12, 13]:
                    standardized_channel = 11
                else:
                    # Para canais 5GHz, mantém como está
                    standardized_channel = channel
                    
                channel_count[standardized_channel] = channel_count.get(standardized_channel, 0) + 1
        
        # Canais não sobrepostos recomendados para 2.4GHz
        recommended_channels_24 = [1, 6, 11]
        
        # Se temos um canal atual, damos prioridade a ele se não estiver muito congestionado
        if current_channel and current_channel in recommended_channels_24:
            current_networks = channel_count.get(current_channel, 0)
            # Se o canal atual tem menos de 5 redes, mantém ele
            if current_networks < 5:
                return current_channel, current_networks
        
        # Encontra o canal menos congestionado
        best_channel = min(recommended_channels_24, key=lambda x: channel_count.get(x, 0))
        congestion_level = channel_count.get(best_channel, 0)
        
        return best_channel, congestion_level

    def check_channel_quality(self, channel):
        """Verifica a qualidade do canal atual"""
        if not channel or channel == 0:
            return "Desconhecido", "N/A"
        
        # Canais não-padrão em 2.4GHz
        if channel in [1, 6, 11]:
            quality = "Excelente"
            reason = f"Canal {channel} é não-sobreposto (ideal)"
        elif 2 <= channel <= 5:
            quality = "Ruim"
            reason = f"Canal {channel} interfere com canal 1"
        elif 7 <= channel <= 10:
            quality = "Ruim"
            reason = f"Canal {channel} interfere com canal 6"
        elif channel == 12 or channel == 13:
            quality = "Ruim"
            reason = f"Canal {channel} interfere com canal 11"
        elif channel >= 36:  # Canais 5GHz
            quality = "Boa"
            reason = f"Canal {channel} (5GHz) tem menos interferência"
        else:
            quality = "Desconhecida"
            reason = f"Canal {channel} não identificado"
        
        return quality, reason

class NetworkSimulator:
    """Simula problemas de rede para testar o sistema de diagnóstico"""
    
    def __init__(self):
        self.simulation_active = False
        self.simulation_type = None
        
    def simulate_problem(self, problem_type, qos_metrics, wireless_devices, network_stats):
        """Simula um problema específico na rede"""
        self.simulation_active = True
        self.simulation_type = problem_type
        
        if problem_type == "high_latency":
            # Simula latência alta
            qos_metrics.update({
                'latency': random.randint(150, 300),
                'jitter': random.randint(40, 80),
                'packet_loss': random.randint(5, 15)
            })
            return "🎭 Simulando: Latência Alta (150-300ms)"
            
        elif problem_type == "packet_loss":
            # Simula perda de pacotes
            qos_metrics.update({
                'latency': random.randint(80, 120),
                'jitter': random.randint(20, 40),
                'packet_loss': random.randint(20, 40)
            })
            return "🎭 Simulando: Perda de Pacotes (20-40%)"
            
        elif problem_type == "channel_congestion":
            # Simula muitos APs no mesmo canal
            for i in range(15):
                fake_bssid = f"02:00:00:00:00:{i:02x}"
                wireless_devices[fake_bssid] = {
                    'type': 'AP',
                    'ssid': f'Fake_Network_{i}',
                    'channel': 6,
                    'last_seen': time.time()
                }
            return "🎭 Simulando: Canal Congestionado (15 redes no canal 6)"
            
        elif problem_type == "deauth_attack":
            # Simula ataque deauthentication
            network_stats['deauth_count'] = 25
            return "🎭 Simulando: Ataque Deauthentication (25 pacotes)"
            
        elif problem_type == "weak_signal":
            # Simula sinal fraco - NOVA SIMULAÇÃO
            return "🎭 Simulando: Sinal Fraco (-75dBm)"
            
        elif problem_type == "mixed_problems":
            # Simula múltiplos problemas
            qos_metrics.update({
                'latency': random.randint(120, 200),
                'jitter': random.randint(30, 60),
                'packet_loss': random.randint(10, 25)
            })
            for i in range(8):
                fake_bssid = f"02:00:00:00:01:{i:02x}"
                wireless_devices[fake_bssid] = {
                    'type': 'AP',
                    'ssid': f'Fake_Network_{i}',
                    'channel': random.choice([1, 6, 11]),
                    'last_seen': time.time()
                }
            return "🎭 Simulando: Múltiplos Problemas (Latência + Congestionamento)"
        
        return "❌ Tipo de simulação não reconhecido"

    def stop_simulation(self, original_metrics, qos_metrics):
        """Para a simulação e restaura métricas originais"""
        qos_metrics.update(original_metrics)
        self.simulation_active = False
        self.simulation_type = None
        return "🛑 Simulação parada - Métricas restauradas"

class DatabaseManager:
    """Gerencia operações com o banco de dados SQLite"""
    
    def __init__(self, db_name="wireless_monitor.db"):
        self.db_name = db_name
    
    def export_data_to_json(self, table_name, filename=None):
        """Exporta dados de uma tabela para JSON"""
        if not filename:
            filename = f"{table_name}_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            conn = sqlite3.connect(self.db_name)
            conn.row_factory = sqlite3.Row  # Para acessar colunas por nome
            cur = conn.cursor()
            
            cur.execute(f"SELECT * FROM {table_name}")
            rows = cur.fetchall()
            
            # Converte para lista de dicionários
            data = [dict(row) for row in rows]
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            conn.close()
            return True, filename, len(data)
        except Exception as e:
            return False, str(e), 0
    
    def get_table_stats(self):
        """Retorna estatísticas das tabelas"""
        tables = ['packets', 'access_points', 'clients', 'qos_metrics', 'network_diagnostics']
        stats = {}
        
        try:
            conn = sqlite3.connect(self.db_name)
            cur = conn.cursor()
            
            for table in tables:
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                count = cur.fetchone()[0]
                stats[table] = count
            
            conn.close()
            return True, stats
        except Exception as e:
            return False, str(e)
    
    def execute_custom_query(self, query):
        """Executa uma consulta SQL personalizada"""
        try:
            conn = sqlite3.connect(self.db_name)
            cur = conn.cursor()
            
            cur.execute(query)
            
            if query.strip().upper().startswith('SELECT'):
                results = cur.fetchall()
                columns = [description[0] for description in cur.description]
                conn.close()
                return True, columns, results
            else:
                conn.commit()
                conn.close()
                return True, None, f"Comando executado: {cur.rowcount} linhas afetadas"
                
        except Exception as e:
            return False, None, str(e)

class WirelessMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Monitor de Rede Sem Fio com Diagnóstico - Linux")
        self.root.geometry("1100x800")
        
        self.is_capturing = False
        self.packets = []
        self.capture_thread = None
        self.qos_thread = None
        self.capture_queue = Queue()
        self.wireless_devices = defaultdict(dict)
        self.network_stats = defaultdict(int)  # Estatísticas de rede
        self.capture_interval = 15
        self.capture_duration = 15
        self.interface = None
        self.interface_map = {}
        
        # ====== SISTEMA DE DIAGNÓSTICO ======
        self.problem_solver = NetworkProblemSolver()
        self.last_diagnosis = []
        
        # ====== SIMULADOR DE PROBLEMAS ======
        self.simulator = NetworkSimulator()
        self.original_metrics = None
        
        # ====== GERENCIADOR DE BANCO DE DADOS ======
        self.db_manager = DatabaseManager()
        # ===========================================
        
        # ====== MÉTRICAS QoS ======
        self.qos_metrics = {
            'latency': 0,
            'jitter': 0,
            'packet_loss': 0,
            'last_update': "Nunca",
            'status': "Não medido"
        }
        self.qos_measurement_count = 0
        self.last_qos_before_capture = None
        
        # ====== INFORMAÇÕES DA REDE WIFI CONECTADA ======
        self.current_wifi_info = {
            'ssid': 'Desconhecido',
            'bssid': 'Desconhecido',
            'channel': 0,
            'frequency': 'Desconhecido',
            'security': 'Desconhecido',
            'signal_strength': "0 dBm"
        }
        # ================================================
        
        self.create_widgets()
        self.setup_styles()
        self.update_interfaces()
        
        # Inicia o monitoramento da rede WiFi conectada
        self.update_wifi_info()
        
        # Inicializa o banco de dados
        self.init_database()
    
    def init_database(self):
        """Cria tabelas se não existirem."""
        try:
            conn = sqlite3.connect(self.db_manager.db_name)
            cur = conn.cursor()
            
            cur.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_mac TEXT,
                dst_mac TEXT,
                bssid TEXT,
                packet_type TEXT,
                size INTEGER,
                raw_log TEXT
            )
            """)
            
            cur.execute("""
            CREATE TABLE IF NOT EXISTS access_points (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ssid TEXT,
                bssid TEXT UNIQUE,
                channel INTEGER,
                signal_strength INTEGER,
                last_seen TEXT
            )
            """)
            
            cur.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT UNIQUE,
                probed_ssid TEXT,
                last_seen TEXT
            )
            """)
            
            # TABELA QoS simplificada
            cur.execute("""
            CREATE TABLE IF NOT EXISTS qos_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                latency REAL,
                jitter REAL,
                packet_loss REAL,
                channel INTEGER,
                measurement_type TEXT
            )
            """)
            
            conn.commit()
            conn.close()
            print(f"[DB] Inicializado {self.db_manager.db_name}")
        except Exception as e:
            print(f"[DB-ERRO] Falha ao inicializar DB: {e}")

    def update_wifi_info(self):
        """Atualiza informações da rede WiFi conectada - APRIMORADA"""
        try:
            # Obtém informações da rede WiFi atual no Linux
            result = subprocess.run(
                ['iwgetid', '-r'], 
                capture_output=True, 
                text=True
            )
            
            if result.returncode == 0 and result.stdout.strip():
                ssid = result.stdout.strip()
                self.current_wifi_info['ssid'] = ssid
                
                # Obtém mais detalhes usando iwconfig
                iw_result = subprocess.run(
                    ['iwconfig'], 
                    capture_output=True, 
                    text=True
                )
                
                signal_dbm = "N/A"
                frequency = "Desconhecido"
                channel = 0
                
                if iw_result.returncode == 0:
                    lines = iw_result.stdout.split('\n')
                    for line in lines:
                        if 'ESSID' in line and ssid in line:
                            # Extrai BSSID
                            if 'Access Point:' in line:
                                bssid = line.split('Access Point:')[1].strip().split()[0]
                                self.current_wifi_info['bssid'] = bssid
                            
                        elif 'Frequency:' in line:
                            # Extrai frequência
                            freq_match = re.search(r'Frequency:([\d\.]+) GHz', line)
                            if freq_match:
                                freq = freq_match.group(1)
                                frequency = f"{freq}GHz"
                                self.current_wifi_info['frequency'] = frequency
                                
                                # Converte frequência para canal - CORRIGIDA
                                try:
                                    freq_float = float(freq)
                                    if 2.4 <= freq_float <= 2.4835:
                                        # Conversão precisa para 2.4GHz
                                        channel = int(round((freq_float - 2.412) / 0.005)) + 1
                                        if channel < 1:
                                            channel = 1
                                        elif channel > 13:
                                            channel = 13
                                    elif 5.0 <= freq_float <= 5.9:
                                        # Conversão para 5GHz (simplificada)
                                        # Canais comuns: 36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161,165
                                        if 5.150 <= freq_float <= 5.250:
                                            channel = 36 + int((freq_float - 5.150) / 0.005)
                                        elif 5.250 <= freq_float <= 5.350:
                                            channel = 52 + int((freq_float - 5.250) / 0.005)
                                        elif 5.470 <= freq_float <= 5.725:
                                            channel = 100 + int((freq_float - 5.470) / 0.005)
                                        elif 5.725 <= freq_float <= 5.825:
                                            channel = 149 + int((freq_float - 5.725) / 0.005)
                                except:
                                    channel = 0
                                
                                self.current_wifi_info['channel'] = channel
                        
                        elif 'Signal level=' in line:
                            # Extrai força do sinal em dBm
                            signal_match = re.search(r'Signal level=(-?\d+) dBm', line)
                            if signal_match:
                                signal_dbm = f"{signal_match.group(1)} dBm"
                                self.current_wifi_info['signal_strength'] = signal_dbm
                            else:
                                # Tenta outros formatos
                                signal_match = re.search(r'Signal level=(-?\d+)/(\d+)', line)
                                if signal_match:
                                    signal = int(signal_match.group(1))
                                    max_signal = int(signal_match.group(2))
                                    if max_signal > 0:
                                        # Conversão aproximada para dBm
                                        dbm = -50 + (signal/max_signal * -50)  # Aproximação
                                        signal_dbm = f"{int(dbm)} dBm"
                                        self.current_wifi_info['signal_strength'] = signal_dbm
                
                # Atualiza a interface
                if hasattr(self, 'wifi_status'):
                    wifi_text = f"WiFi: {ssid} | Canal: {channel} | Sinal: {signal_dbm}"
                    self.wifi_status.config(text=wifi_text)
                    
                    # Altera cor baseada na força do sinal
                    try:
                        dbm_value = int(signal_dbm.split()[0])
                        if dbm_value >= -50:
                            self.wifi_status.config(foreground="green")
                        elif dbm_value >= -65:
                            self.wifi_status.config(foreground="orange")
                        else:
                            self.wifi_status.config(foreground="red")
                    except:
                        pass
                    
                    # Adiciona alerta visual se canal não for padrão
                    if channel not in [1, 6, 11] and 1 <= channel <= 13:
                        self.wifi_status.config(font=('Arial', 9, 'bold'))
            
            else:
                self.current_wifi_info['ssid'] = 'Não conectado'
                self.current_wifi_info['signal_strength'] = "N/A"
                if hasattr(self, 'wifi_status'):
                    self.wifi_status.config(text="WiFi: Não conectado", foreground="red")
                    
        except Exception as e:
            print(f"Erro ao obter informações WiFi: {e}")
        
        # Agenda próxima atualização
        self.root.after(10000, self.update_wifi_info)  # Atualiza a cada 10 segundos

    def frequency_to_channel_24(self, frequency):
        """Converte frequência para canal na banda 2.4GHz - CORRIGIDA"""
        try:
            # Remove 'GHz' e converte para float
            freq_ghz = float(frequency.replace('GHz', '').strip())
            
            # Tabela de frequência para canal 2.4GHz
            # Canal 1: 2.412 GHz
            # Canal 2: 2.417 GHz
            # ...
            # Canal 13: 2.472 GHz
            
            if freq_ghz >= 2.412 and freq_ghz <= 2.484:
                # Fórmula: canal = ((freq_ghz - 2.412) / 0.005) + 1
                channel = int(((freq_ghz - 2.412) / 0.005) + 1)
                
                # Arredonda para o canal mais próximo
                channel = round(channel)
                
                # Limita aos canais válidos
                if channel < 1:
                    channel = 1
                elif channel > 13:
                    channel = 13
                    
                return channel
        except:
            pass
        return 0
    
    def frequency_to_channel_5(self, frequency):
        """Converte frequência para canal na banda 5GHz - CORRIGIDA"""
        try:
            freq_ghz = float(frequency.replace('GHz', '').strip())
            
            # Tabela de canais 5GHz
            if 5.180 <= freq_ghz <= 5.200:
                return 36
            elif 5.200 <= freq_ghz <= 5.220:
                return 40
            elif 5.220 <= freq_ghz <= 5.240:
                return 44
            elif 5.240 <= freq_ghz <= 5.260:
                return 48
            elif 5.260 <= freq_ghz <= 5.280:
                return 52
            elif 5.280 <= freq_ghz <= 5.300:
                return 56
            elif 5.300 <= freq_ghz <= 5.320:
                return 60
            elif 5.320 <= freq_ghz <= 5.340:
                return 64
            elif 5.500 <= freq_ghz <= 5.520:
                return 100
            elif 5.520 <= freq_ghz <= 5.540:
                return 104
            elif 5.540 <= freq_ghz <= 5.560:
                return 108
            elif 5.560 <= freq_ghz <= 5.580:
                return 112
            elif 5.580 <= freq_ghz <= 5.600:
                return 116
            elif 5.600 <= freq_ghz <= 5.620:
                return 120
            elif 5.620 <= freq_ghz <= 5.640:
                return 124
            elif 5.640 <= freq_ghz <= 5.660:
                return 128
            elif 5.660 <= freq_ghz <= 5.680:
                return 132
            elif 5.680 <= freq_ghz <= 5.700:
                return 136
            elif 5.700 <= freq_ghz <= 5.720:
                return 140
            elif 5.745 <= freq_ghz <= 5.765:
                return 149
            elif 5.765 <= freq_ghz <= 5.785:
                return 153
            elif 5.785 <= freq_ghz <= 5.805:
                return 157
            elif 5.805 <= freq_ghz <= 5.825:
                return 161
            elif 5.825 <= freq_ghz <= 5.845:
                return 165
                
        except:
            pass
        return 0

    # ----------------- Banco de dados -----------------
    def save_packet_to_db(self, timestamp, src_mac, dst_mac, bssid, packet_type, size, raw_log):
        """Insere registro de pacote no DB."""
        try:
            conn = sqlite3.connect(self.db_manager.db_name)
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO packets (timestamp, src_mac, dst_mac, bssid, packet_type, size, raw_log)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, src_mac, dst_mac, bssid, packet_type, size, raw_log))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB-ERRO] Falha ao salvar pacote: {e}")

    def save_qos_metrics(self, latency, jitter, packet_loss, measurement_type="normal"):
        """Salva métricas QoS no banco."""
        try:
            conn = sqlite3.connect(self.db_manager.db_name)
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO qos_metrics (timestamp, latency, jitter, packet_loss, measurement_type)
                VALUES (?, ?, ?, ?, ?)
            """, (
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                latency,
                jitter,
                packet_loss,
                measurement_type
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB-ERRO] Falha ao salvar métricas QoS: {e}")

    def save_ap_to_db(self, ssid, bssid, channel, last_seen, signal_strength=-65):
        """Insere/atualiza AP no DB."""
        try:
            conn = sqlite3.connect(self.db_manager.db_name)
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO access_points (ssid, bssid, channel, signal_strength, last_seen)
                VALUES (?, ?, ?, ?, ?)
            """, (ssid, bssid, channel, signal_strength, last_seen))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB-ERRO] Falha ao salvar AP: {e}")

    def save_client_to_db(self, mac, probed_ssid, last_seen):
        """Insere/atualiza cliente no DB."""
        try:
            conn = sqlite3.connect(self.db_manager.db_name)
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO clients (mac, probed_ssid, last_seen)
                VALUES (?, ?, ?)
            """, (mac, probed_ssid, last_seen))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB-ERRO] Falha ao salvar client: {e}")

    def show_database_manager(self):
        """Interface para gerenciar o banco de dados"""
        db_window = tk.Toplevel(self.root)
        db_window.title("Gerenciador de Banco de Dados")
        db_window.geometry("800x600")
        
        main_frame = ttk.Frame(db_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Estatísticas ATUALIZADAS com dados mais recentes
        stats_frame = ttk.LabelFrame(main_frame, text="📊 Estatísticas do Banco de Dados (Dados Recentes)", padding=10)
        stats_frame.pack(fill=tk.X, pady=5)
        
        success, stats = self.db_manager.get_table_stats()
        if success:
            stats_text = ""
            for table, count in stats.items():
                stats_text += f"• {table}: {count} registros\n"
            
            # Adiciona informações sobre dados recentes
            stats_text += f"\n📅 Última atualização: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n"
            stats_text += f"📶 Redes detectadas: {len([d for d in self.wireless_devices.values() if d.get('type') == 'AP'])}\n"
            stats_text += f"📱 Dispositivos: {len([d for d in self.wireless_devices.values() if d.get('type') == 'Client'])}\n"
            stats_text += f"⚡ Simulação ativa: {'Sim' if self.simulator.simulation_active else 'Não'}\n"
        else:
            stats_text = f"Erro: {stats}"
        
        stats_label = ttk.Label(stats_frame, text=stats_text)
        stats_label.pack(anchor='w')
        
        # Exportação
        export_frame = ttk.LabelFrame(main_frame, text="💾 Exportar Dados", padding=10)
        export_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(export_frame, text="Tabela para exportar:").grid(row=0, column=0, padx=5, sticky='w')
        export_var = tk.StringVar(value="packets")
        export_combo = ttk.Combobox(export_frame, textvariable=export_var, 
                                   values=["packets", "access_points", "clients", "qos_metrics", "network_diagnostics"])
        export_combo.grid(row=0, column=1, padx=5)
        
        def export_data():
            table = export_var.get()
            success, result, count = self.db_manager.export_data_to_json(table)
            if success:
                messagebox.showinfo("Exportação Concluída", 
                                  f"Dados exportados para: {result}\nTotal: {count} registros")
            else:
                messagebox.showerror("Erro na Exportação", result)
        
        ttk.Button(export_frame, text="Exportar para JSON", 
                  command=export_data, style='Green.TButton').grid(row=0, column=2, padx=5)
        
        # Consulta personalizada
        query_frame = ttk.LabelFrame(main_frame, text="🔍 Consulta SQL Personalizada", padding=10)
        query_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        query_text = scrolledtext.ScrolledText(query_frame, height=6, font=('Consolas', 9))
        query_text.pack(fill=tk.X, pady=5)
        query_text.insert(tk.END, "SELECT * FROM packets LIMIT 10;")
        
        result_text = scrolledtext.ScrolledText(query_frame, height=10, font=('Consolas', 9))
        result_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        def execute_query():
            query = query_text.get(1.0, tk.END).strip()
            success, columns, results = self.db_manager.execute_custom_query(query)
            
            result_text.delete(1.0, tk.END)
            if success:
                if columns:  # É uma consulta SELECT
                    result_text.insert(tk.END, " | ".join(columns) + "\n")
                    result_text.insert(tk.END, "-" * 80 + "\n")
                    for row in results[:100]:  # Limita a 100 linhas
                        result_text.insert(tk.END, " | ".join(map(str, row)) + "\n")
                    if len(results) > 100:
                        result_text.insert(tk.END, f"\n... e mais {len(results) - 100} linhas")
                else:
                    result_text.insert(tk.END, str(results))
            else:
                result_text.insert(tk.END, f"ERRO: {results}")
        
        ttk.Button(query_frame, text="Executar Consulta", 
                  command=execute_query, style='Blue.TButton').pack(pady=5)

    # ----------------- Funções QoS -----------------
    def measure_qos(self):
        """Mede latência, jitter e perda de pacotes - SÓ FUNCIONA COM REDE NORMAL"""
        try:
            target = '8.8.8.8'  # Google DNS
            
            self.capture_queue.put(f"[QoS] Medindo latência para {target}...\n")
            
            ping_result = subprocess.run(
                ['ping', '-c', '4', target],
                capture_output=True, 
                text=True,
                timeout=10
            )
            
            if ping_result.returncode == 0:
                times = []
                for line in ping_result.stdout.split('\n'):
                    if 'time=' in line:
                        try:
                            time_str = line.split('time=')[1].split(' ')[0]
                            times.append(float(time_str))
                        except (IndexError, ValueError):
                            continue
                
                if times:
                    latency = sum(times) / len(times)
                    jitter = max(times) - min(times) if len(times) > 1 else 0
                    packet_loss = ((4 - len(times)) / 4) * 100
                    
                    self.qos_metrics.update({
                        'latency': round(latency, 2),
                        'jitter': round(jitter, 2),
                        'packet_loss': round(packet_loss, 2),
                        'last_update': datetime.datetime.now().strftime("%H:%M:%S"),
                        'status': "Medido"
                    })
                    
                    # Salva no banco
                    self.save_qos_metrics(latency, jitter, packet_loss)
                    
                    # Adiciona aos logs
                    qos_info = (
                        f"[QoS] Latência: {self.qos_metrics['latency']}ms | "
                        f"Jitter: {self.qos_metrics['jitter']}ms | "
                        f"Perda: {self.qos_metrics['packet_loss']}% | "
                        f"Atualizado: {self.qos_metrics['last_update']}\n"
                    )
                    self.capture_queue.put(qos_info)
                    
                    # Atualiza status
                    self.update_qos_status()
                    
                    self.qos_measurement_count += 1
                    return True
                else:
                    self.capture_queue.put("[QoS] Nenhum pacote recebido no ping\n")
                    self.qos_metrics['status'] = "Falha na medição"
            else:
                self.capture_queue.put(f"[QoS] Erro no comando ping: {ping_result.stderr}\n")
                self.qos_metrics['status'] = "Falha na medição"
                    
        except subprocess.TimeoutExpired:
            self.capture_queue.put("[QoS] Timeout na medição (10s)\n")
            self.qos_metrics['status'] = "Timeout"
        except Exception as e:
            self.capture_queue.put(f"[QoS] Erro: {str(e)}\n")
            self.qos_metrics['status'] = "Erro"
            
        return False

    def update_qos_status(self):
        """Atualiza o status das métricas QoS na interface."""
        if self.qos_metrics['status'] == "Não medido":
            status_text = "QoS: Não medido"
        elif self.qos_metrics['status'] == "Medido":
            status_text = (
                f"QoS: {self.qos_metrics['latency']}ms | "
                f"Jitter: {self.qos_metrics['jitter']}ms | "
                f"Perda: {self.qos_metrics['packet_loss']}%"
            )
        else:
            status_text = f"QoS: {self.qos_metrics['status']}"
        
        self.qos_status.config(text=status_text)

    def measure_qos_before_capture(self):
        """Mede QoS antes de iniciar o monitoramento (rede normal)"""
        self.capture_queue.put("\n📊 MEDINDO QoS ANTES DO MONITORAMENTO...\n")
        if self.measure_qos():
            self.last_qos_before_capture = self.qos_metrics.copy()
            self.save_qos_metrics(
                self.qos_metrics['latency'],
                self.qos_metrics['jitter'], 
                self.qos_metrics['packet_loss'],
                "before_capture"
            )
            return True
        return False

    def measure_qos_after_capture(self):
        """Mede QoS após parar o monitoramento (rede restaurada)"""
        self.capture_queue.put("\n📊 MEDINDO QoS APÓS O MONITORAMENTO...\n")
        if self.measure_qos():
            after_metrics = self.qos_metrics.copy()
            self.save_qos_metrics(
                after_metrics['latency'],
                after_metrics['jitter'],
                after_metrics['packet_loss'],
                "after_capture"
            )
            
            # Compara com medição anterior se disponível
            if self.last_qos_before_capture:
                self._compare_qos_measurements()
            
            return True
        return False

    def _compare_qos_measurements(self):
        """Compara medições QoS antes e depois do monitoramento"""
        before = self.last_qos_before_capture
        after = self.qos_metrics
        
        latency_diff = before['latency'] - after['latency']
        latency_change = "melhorou" if latency_diff > 0 else "piorou"
        
        packet_loss_diff = before['packet_loss'] - after['packet_loss']
        packet_loss_change = "melhorou" if packet_loss_diff > 0 else "piorou"
        
        comparison = (
            f"\n📈 COMPARAÇÃO QoS (Antes vs Depois):\n"
            f"   Latência: {before['latency']}ms → {after['latency']}ms ({latency_change})\n"
            f"   Perda: {before['packet_loss']}% → {after['packet_loss']}% ({packet_loss_change})\n"
            f"   Jitter: {before['jitter']}ms → {after['jitter']}ms\n"
        )
        
        self.capture_queue.put(comparison)

    # ----------------- Sistema de Diagnóstico -----------------
    def run_network_diagnosis(self):
        """Executa diagnóstico completo da rede - APRIMORADO"""
        self.capture_queue.put("\n🔍 INICIANDO DIAGNÓSTICO DE REDE...\n")
        
        # Mostra informações atuais
        self.capture_queue.put(f"📊 INFORMAÇÕES ATUAIS:\n")
        self.capture_queue.put(f"   SSID: {self.current_wifi_info['ssid']}\n")
        self.capture_queue.put(f"   Canal: {self.current_wifi_info['channel']}\n")
        self.capture_queue.put(f"   Sinal: {self.current_wifi_info['signal_strength']}\n")
        
        # Se há simulação ativa, usa métricas simuladas
        if self.simulator.simulation_active:
            self.capture_queue.put("🎭 DIAGNÓSTICO COM SIMULAÇÃO ATIVA\n")
            self.capture_queue.put(f"📊 Analisando problema simulado: {self.simulator.simulation_type}\n")
        
        # Coleta dados atuais (podem ser simulados ou reais)
        current_qos = self.qos_metrics.copy()
        
        # Executa diagnóstico incluindo informações da WiFi conectada
        problems = self.problem_solver.analyze_network_health(
            current_qos, 
            self.wireless_devices,
            self.capture_queue,
            self.network_stats,
            self.current_wifi_info
        )
        
        self.last_diagnosis = problems
        
        # Mostra relatório
        report = self.problem_solver.generate_detailed_report(problems, self.current_wifi_info)
        
        # Cria janela de resultados
        self.show_diagnosis_results(report, problems)

    def show_diagnosis_results(self, report, problems):
        """Mostra resultados do diagnóstico em nova janela"""
        diagnosis_window = tk.Toplevel(self.root)
        diagnosis_window.title("Diagnóstico de Rede - Resultados")
        diagnosis_window.geometry("800x600")
        
        # Frame principal
        main_frame = ttk.Frame(diagnosis_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Título
        title_label = ttk.Label(main_frame, text="🔍 Diagnóstico da Rede", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Informações da WiFi conectada
        wifi_info = f"📶 Conectado a: {self.current_wifi_info['ssid']} | " \
                   f"Canal: {self.current_wifi_info['channel']} | " \
                   f"Sinal: {self.current_wifi_info['signal_strength']}\n\n"
        
        # Verifica qualidade do canal
        if self.current_wifi_info['channel']:
            quality, reason = self.problem_solver.check_channel_quality(self.current_wifi_info['channel'])
            wifi_info += f"📊 Qualidade do canal {self.current_wifi_info['channel']}: {quality}\n"
            wifi_info += f"   💡 {reason}\n\n"
        
        # Informações de simulação se ativa
        if self.simulator.simulation_active:
            sim_info = f"🎭 SIMULAÇÃO ATIVA: {self.simulator.simulation_type}\n\n"
            wifi_info = sim_info + wifi_info
        
        # Área de texto com scroll
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text_area = scrolledtext.ScrolledText(
            text_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#f8f9fa'
        )
        text_area.pack(fill=tk.BOTH, expand=True)
        text_area.insert(tk.END, wifi_info + report)
        text_area.config(state=tk.DISABLED)
        
        # Botões de ação
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        if problems:
            ttk.Button(
                button_frame,
                text="💡 Ver Soluções Rápidas",
                command=lambda: self.show_quick_fixes(problems),
                style='Orange.TButton'
            ).pack(side=tk.LEFT, padx=5)
            
            ttk.Button(
                button_frame,
                text="📊 Canal Recomendado",
                command=self.show_recommended_channel,
                style='Green.TButton'
            ).pack(side=tk.LEFT, padx=5)
            
            ttk.Button(
                button_frame,
                text="🔍 Detalhes do Canal",
                command=self.show_channel_details,
                style='Blue.TButton'
            ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Fechar",
            command=diagnosis_window.destroy,
            style='Red.TButton'
        ).pack(side=tk.RIGHT, padx=5)

    def show_quick_fixes(self, problems):
        """Mostra soluções rápidas"""
        quick_fixes = self.problem_solver.get_quick_fixes(problems)
        
        fixes_text = "🚀 SOLUÇÕES RÁPIDAS:\n\n"
        for i, fix in enumerate(quick_fixes, 1):
            fixes_text += f"{i}. {fix}\n"
        
        messagebox.showinfo("Soluções Rápidas", fixes_text)

    def show_recommended_channel(self):
        """Mostra o canal recomendado baseado na análise"""
        best_channel, congestion = self.problem_solver.get_recommended_channel(
            self.wireless_devices, 
            self.current_wifi_info.get('channel')
        )
        
        current_channel = self.current_wifi_info.get('channel', 0)
        
        channel_info = (
            f"📊 ANÁLISE DE CANAIS\n\n"
            f"🎯 Canal Atual: {current_channel}\n"
            f"⭐ Canal Recomendado: {best_channel}\n"
            f"📶 Redes no canal recomendado: {congestion}\n"
            f"💡 Canais não-sobrepostos (2.4GHz): 1, 6, 11\n\n"
        )
        
        if current_channel not in [1, 6, 11] and 1 <= current_channel <= 13:
            channel_info += (
                f"⚠️  SEU CANAL ATUAL ({current_channel}) NÃO É RECOMENDADO!\n"
                f"   • Canais 2,3,4,5 interferem com canal 1\n"
                f"   • Canais 7,8,9,10 interferem com canal 6\n"
                f"   • Canais 12,13 interferem com canal 11\n\n"
            )
        
        channel_info += (
            f"PARA MELHORAR SUA REDE:\n"
            f"1. Acesse as configurações do roteador (192.168.1.1 ou 192.168.0.1)\n"
            f"2. Vá para Wireless/Configurações WiFi\n"
            f"3. Mude para o canal {best_channel}\n"
            f"4. Salve as configurações\n"
            f"5. Reinicie o roteador se necessário\n\n"
            f"💡 Dica: Use a banda 5GHz se disponível para menos interferência!"
        )
        
        messagebox.showinfo("Canal Recomendado", channel_info)

    def show_channel_details(self):
        """Mostra detalhes sobre o canal atual"""
        channel = self.current_wifi_info.get('channel', 0)
        signal = self.current_wifi_info.get('signal_strength', 'N/A')
        
        if not channel:
            messagebox.showinfo("Informações do Canal", "Canal não detectado.")
            return
        
        quality, reason = self.problem_solver.check_channel_quality(channel)
        
        details = (
            f"📡 DETALHES DO CANAL {channel}\n\n"
            f"📊 Qualidade: {quality}\n"
            f"💡 {reason}\n\n"
            f"📶 Sinal atual: {signal}\n"
        )
        
        # Adiciona informações específicas baseadas no canal
        if 1 <= channel <= 13:
            details += f"\n🌐 Banda: 2.4GHz\n"
            if channel in [1, 6, 11]:
                details += f"✅ Este é um canal não-sobreposto (ideal)\n"
            else:
                details += f"⚠️  Este é um canal sobreposto (não ideal)\n"
                
            # Mostra canais que interferem
            if 2 <= channel <= 5:
                details += f"📡 Interfere com: Canal 1\n"
            elif 7 <= channel <= 10:
                details += f"📡 Interfere com: Canal 6\n"
            elif channel == 12 or channel == 13:
                details += f"📡 Interfere com: Canal 11\n"
                
        elif channel >= 36:
            details += f"\n🌐 Banda: 5GHz\n"
            details += f"✅ Menos interferência que 2.4GHz\n"
            details += f"💡 Melhor para streaming e jogos\n"
        
        # Recomendação de sinal
        try:
            if 'dBm' in signal:
                dbm = int(re.search(r'(-?\d+)', signal).group(1))
                if dbm >= -50:
                    details += f"\n📶 Sinal: Excelente ({dbm}dBm)\n"
                elif dbm >= -65:
                    details += f"\n📶 Sinal: Bom ({dbm}dBm)\n"
                elif dbm >= -75:
                    details += f"\n⚠️  Sinal: Fraco ({dbm}dBm)\n"
                    details += f"   Considere aproximar-se do roteador\n"
                else:
                    details += f"\n❌ Sinal: Muito Fraco ({dbm}dBm)\n"
                    details += f"   Pode causar desconexões\n"
        except:
            pass
        
        messagebox.showinfo("Detalhes do Canal", details)

    # ----------------- Simulador de Problemas -----------------
    def show_simulation_menu(self):
        """Menu para simular problemas de rede - ATUALIZADO"""
        sim_window = tk.Toplevel(self.root)
        sim_window.title("Simulador de Problemas de Rede")
        sim_window.geometry("500x450")
        
        main_frame = ttk.Frame(sim_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(main_frame, text="🎭 SIMULADOR DE PROBLEMAS", 
                 font=('Arial', 14, 'bold')).pack(pady=10)
        
        ttk.Label(main_frame, text="Selecione o problema a simular:", 
                 font=('Arial', 10)).pack(pady=5)
        
        # Botões de simulação
        problems = [
            ("🚨 Latência Alta", "high_latency"),
            ("📉 Perda de Pacotes", "packet_loss"), 
            ("📶 Canal Congestionado", "channel_congestion"),
            ("📡 Sinal Fraco", "weak_signal"),  # NOVO
            ("⚡ Ataque Deauthentication", "deauth_attack"),
            ("🔀 Múltiplos Problemas", "mixed_problems")
        ]
        
        for text, problem_type in problems:
            btn = ttk.Button(
                main_frame,
                text=text,
                command=lambda pt=problem_type: self.start_simulation(pt),
                style='Orange.TButton',
                width=30
            )
            btn.pack(pady=5)
        
        # Botão para parar simulação
        ttk.Button(
            main_frame,
            text="🛑 Parar Simulação",
            command=self.stop_simulation,
            style='Red.TButton',
            width=30
        ).pack(pady=10)
        
        # Status da simulação
        self.sim_status = ttk.Label(main_frame, text="Status: Nenhuma simulação ativa", 
                                   foreground="green")
        self.sim_status.pack(pady=5)
        
        # Informações atuais
        info_frame = ttk.LabelFrame(main_frame, text="📊 Estado Atual", padding=10)
        info_frame.pack(fill=tk.X, pady=10)
        
        current_info = (
            f"Sinal: {self.current_wifi_info.get('signal_strength', 'N/A')}\n"
            f"Canal: {self.current_wifi_info.get('channel', 'N/A')}\n"
            f"Redes detectadas: {len([d for d in self.wireless_devices.values() if d.get('type') == 'AP'])}"
        )
        
        ttk.Label(info_frame, text=current_info).pack()

    def start_simulation(self, problem_type):
        """Inicia simulação de problema"""
        if self.simulator.simulation_active:
            messagebox.showwarning("Aviso", "Já existe uma simulação ativa!")
            return
        
        # Salva métricas originais ANTES da simulação
        self.original_metrics = {
            'latency': self.qos_metrics['latency'],
            'jitter': self.qos_metrics['jitter'],
            'packet_loss': self.qos_metrics['packet_loss']
        }
        
        # Inicia simulação
        result = self.simulator.simulate_problem(
            problem_type, 
            self.qos_metrics, 
            self.wireless_devices,
            self.network_stats
        )
        
        self.simulator.simulation_active = True
        self.simulator.simulation_type = problem_type
        
        self.capture_queue.put(f"\n{result}\n")
        self.sim_status.config(text=f"Status: Simulando {problem_type}", foreground="red")
        
        # Atualiza o status QoS para refletir a simulação
        self.update_qos_status()
        
        messagebox.showinfo("Simulação Iniciada", 
                          f"Simulação '{problem_type}' iniciada!\nExecute o diagnóstico para ver a detecção.")

    def stop_simulation(self):
        """Para a simulação"""
        if not self.simulator.simulation_active:
            messagebox.showinfo("Info", "Nenhuma simulação ativa!")
            return
        
        if self.original_metrics:
            result = self.simulator.stop_simulation(self.original_metrics, self.qos_metrics)
            self.capture_queue.put(f"\n{result}\n")
            self.sim_status.config(text="Status: Nenhuma simulação ativa", foreground="green")
            self.update_qos_status()
            
            # Limpa redes falsas da simulação
            fake_bssids = [bssid for bssid, info in self.wireless_devices.items() 
                          if info.get('ssid', '').startswith('Fake_Network_')]
            for bssid in fake_bssids:
                del self.wireless_devices[bssid]
                
            # Reseta estatísticas de deauth se era uma simulação
            if self.simulator.simulation_type == 'deauth_attack':
                self.network_stats['deauth_count'] = 0
        else:
            messagebox.showerror("Erro", "Não foi possível restaurar métricas originais!")

    # ----------------- Funções de Rede -----------------
    def set_monitor_mode(self, interface):
        """Ativa o modo monitor no Linux usando airmon-ng"""
        try:
            # Verifica se a interface existe
            try:
                subprocess.run(["iwconfig", interface], check=True, capture_output=True)
            except:
                messagebox.showerror("Erro", f"Interface {interface} não encontrada!")
                return None

            # Para processos interferentes
            subprocess.run(["sudo", "airmon-ng", "check", "kill"], capture_output=True)

            # Ativa modo monitor
            result = subprocess.run(
                ["sudo", "airmon-ng", "start", interface],
                capture_output=True, text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Erro", f"Falha ao ativar modo monitor: {result.stderr}")
                return None

            # Procura pela interface em modo monitor
            iwconfig_result = subprocess.run(["iwconfig"], capture_output=True, text=True)
            
            for line in iwconfig_result.stdout.split('\n'):
                if "IEEE 802.11" in line and "Mode:Monitor" in line:
                    iface_name = line.split()[0]
                    return iface_name
            
            # Tenta nomes comuns
            for name in [f"{interface}mon", "mon0", "wlan0mon"]:
                try:
                    subprocess.run(["iwconfig", name], check=True, capture_output=True)
                    return name
                except:
                    continue
            
            messagebox.showerror("Erro", "Não foi possível encontrar interface em modo monitor")
            return None
            
        except Exception as e:
            messagebox.showerror("Erro", f"Erro inesperado: {str(e)}")
            return None
    
    def stop_monitor_mode(self, interface):
        """Desativa o modo monitor e restaura o NetworkManager"""
        try:
            # Primeiro para o modo monitor
            if interface:
                subprocess.run(["sudo", "airmon-ng", "stop", interface], check=True)
            
            # Restaura o NetworkManager
            self.capture_queue.put("[SISTEMA] Restaurando NetworkManager...\n")
            result = subprocess.run(
                ["sudo", "systemctl", "start", "NetworkManager"],
                capture_output=True, 
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.capture_queue.put("[SISTEMA] NetworkManager reiniciado com sucesso\n")
                self.capture_queue.put("[SISTEMA] Conectividade normal restaurada\n")
            else:
                self.capture_queue.put(f"[AVISO] NetworkManager não pôde ser reiniciado: {result.stderr}\n")
            
            return True
            
        except subprocess.TimeoutExpired:
            self.capture_queue.put("[AVISO] Timeout ao restaurar NetworkManager\n")
            return False
        except subprocess.CalledProcessError as e:
            self.capture_queue.put(f"[AVISO] Erro ao restaurar NetworkManager: {e.stderr}\n")
            return False
        except Exception as e:
            self.capture_queue.put(f"[AVISO] Erro inesperado ao restaurar NetworkManager: {str(e)}\n")
            return False
    
    def setup_styles(self):
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TButton', font=('Arial', 10), padding=5)
        self.style.configure('Red.TButton', foreground='white', background='#d9534f')
        self.style.configure('Green.TButton', foreground='white', background='#5cb85c')
        self.style.configure('Blue.TButton', foreground='white', background='#5bc0de')
        self.style.configure('Orange.TButton', foreground='white', background='#f0ad4e')
        self.style.configure('TLabelframe', background='#f0f0f0')
        self.style.configure('TLabelframe.Label', background='#f0f0f0')
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Frame de monitoramento
        monitor_frame = ttk.LabelFrame(main_frame, text="Monitoramento de Rede Sem Fio", padding=10)
        monitor_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(monitor_frame, text="Interface de rede:").grid(row=0, column=0, padx=5, sticky='w')
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(monitor_frame, textvariable=self.interface_var, width=30)
        self.interface_combo.grid(row=0, column=1, padx=5, sticky='w')
        
        ttk.Button(
            monitor_frame,
            text="Atualizar Interfaces",
            command=self.update_interfaces,
            style='Blue.TButton'
        ).grid(row=0, column=2, padx=5)
        
        ttk.Label(monitor_frame, text="Intervalo (s):").grid(row=1, column=0, padx=5, sticky='w')
        self.interval_var = tk.StringVar(value="15")
        ttk.Spinbox(monitor_frame, from_=5, to=300, textvariable=self.interval_var, width=5).grid(row=1, column=1, padx=5, sticky='w')
        
        ttk.Label(monitor_frame, text="Duração (s):").grid(row=1, column=2, padx=5, sticky='w')
        self.duration_var = tk.StringVar(value="15")
        ttk.Spinbox(monitor_frame, from_=5, to=60, textvariable=self.duration_var, width=5).grid(row=1, column=3, padx=5, sticky='w')
        
        # Botões de controle
        monitor_btn_frame = ttk.Frame(monitor_frame)
        monitor_btn_frame.grid(row=2, column=0, columnspan=4, pady=10)
        
        self.start_button = ttk.Button(
            monitor_btn_frame, 
            text="▶ Iniciar Monitoramento", 
            command=self.start_capture,
            style='Green.TButton'
        )
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(
            monitor_btn_frame, 
            text="⏹ Parar Monitoramento", 
            command=self.stop_capture,
            style='Red.TButton',
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            monitor_btn_frame, 
            text="🔍 Diagnóstico", 
            command=self.run_network_diagnosis,
            style='Orange.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            monitor_btn_frame, 
            text="📊 Análise", 
            command=self.show_network_analysis,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            monitor_btn_frame, 
            text="🧪 Medir QoS", 
            command=self.measure_qos,
            style='Green.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            monitor_btn_frame, 
            text="📈 Canal Recomendado", 
            command=self.show_recommended_channel,
            style='Orange.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        # NOVO: Botão para simulador de problemas
        ttk.Button(
            monitor_btn_frame, 
            text="🎭 Simular Problemas", 
            command=self.show_simulation_menu,
            style='Red.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            monitor_btn_frame, 
            text="💾 Banco de Dados", 
            command=self.show_database_manager,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            monitor_btn_frame, 
            text="🗑 Limpar", 
            command=self.clear_all,
            style='Red.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        # Status
        status_frame = ttk.Frame(monitor_frame)
        status_frame.grid(row=3, column=0, columnspan=4, pady=5, sticky='ew')
        
        self.capture_status = ttk.Label(status_frame, text="Monitoramento: Inativo", foreground="red")
        self.capture_status.pack(side=tk.LEFT)
        
        self.network_count = ttk.Label(status_frame, text="Redes detectadas: 0")
        self.network_count.pack(side=tk.LEFT, padx=20)
        
        self.device_count = ttk.Label(status_frame, text="Dispositivos: 0")
        self.device_count.pack(side=tk.LEFT, padx=20)
        
        self.qos_status = ttk.Label(status_frame, text="QoS: Não medido")
        self.qos_status.pack(side=tk.LEFT, padx=20)
        
        # NOVO: Status da WiFi conectada
        self.wifi_status = ttk.Label(status_frame, text="WiFi: Não conectado", foreground="blue")
        self.wifi_status.pack(side=tk.LEFT, padx=20)
        
        # Área de log
        self.log_area = scrolledtext.ScrolledText(
            main_frame, 
            width=110, 
            height=25,
            wrap=tk.WORD,
            font=('Consolas', 9)
        )
        self.log_area.pack(fill=tk.BOTH, expand=True)
        self.log_area.insert(tk.END, "Sistema pronto. Selecione a interface e inicie o monitoramento.\n")
        self.log_area.insert(tk.END, "🔍 SISTEMA DE DIAGNÓSTICO DE PROBLEMAS WiFi\n")
        self.log_area.insert(tk.END, "⚠️  QoS só pode ser medido com rede normal (antes/depois do monitoramento)\n")
        self.log_area.insert(tk.END, "📊  Use 'Medir QoS' quando a rede estiver funcionando normalmente\n")
        self.log_area.insert(tk.END, "🎭  Use 'Simular Problemas' para testar o sistema de diagnóstico\n")
        self.log_area.insert(tk.END, "💾  Use 'Banco de Dados' para exportar e analisar logs SQLite\n")
        self.log_area.insert(tk.END, "💡  Use 'Diagnóstico' para analisar problemas e obter soluções\n")
        self.log_area.insert(tk.END, "📶  Monitoramento da WiFi conectada ativo\n")
        self.log_area.insert(tk.END, "⚠️  Alerta: Canais não-padrão (2,3,4,5,7,8,9,10,12,13) serão detectados\n")
    
    def update_interfaces(self):
        """Lista interfaces Wi-Fi no Linux"""
        self.interface_map.clear()
        display_names = []
        
        try:
            result = subprocess.run(["iwconfig"], capture_output=True, text=True, check=True)
            
            for line in result.stdout.split('\n'):
                if "IEEE 802.11" in line:
                    iface_name = line.split()[0]
                    display_name = f"{iface_name} (Wi-Fi)"
                    self.interface_map[display_name] = iface_name
                    display_names.append(display_name)
            
            display_names.sort()
            self.interface_combo['values'] = display_names
            
            if display_names:
                self.interface_combo.set(display_names[0])
                self.log_area.insert(tk.END, "\nInterfaces disponíveis atualizadas.\n")
            else:
                self.log_area.insert(tk.END, "\nNenhuma interface wireless encontrada!\n")
                
        except Exception as e:
            error_msg = f"\n[ERRO] Falha ao listar interfaces: {str(e)}\n"
            self.log_area.insert(tk.END, error_msg)
    
    def get_selected_interface(self):
        display_name = self.interface_var.get()
        return self.interface_map.get(display_name)
    
    def packet_handler(self, packet):
        try:
            if packet.haslayer(Dot11):
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                
                mac_src = packet.addr2 if packet.addr2 else "Desconhecido"
                mac_dst = packet.addr1 if packet.addr1 else "Desconhecido"
                bssid = packet.addr3 if packet.addr3 else "Desconhecido"
                
                packet_type = "Desconhecido"
                packet_info = f"\n[{timestamp}] "
                
                # Contagem de tipos de pacotes
                if packet.haslayer(Dot11Beacon):
                    packet_type = "Beacon"
                    self.network_stats['beacon_count'] += 1
                    ssid = packet[Dot11Beacon].info.decode('utf-8', errors='ignore') if packet[Dot11Beacon].info else "Hidden"
                    try:
                        # Extrai canal do elemento DS Parameter
                        channel = None
                        if packet.haslayer(Dot11Elt):
                            for i in range(0, len(packet[Dot11Elt])):
                                if packet[Dot11Elt][i].ID == 3:  # DS Parameter
                                    channel = int(packet[Dot11Elt][i].info.hex(), 16)
                                    break
                    except Exception:
                        channel = None
                    
                    self.wireless_devices[bssid]['type'] = "AP"
                    self.wireless_devices[bssid]['ssid'] = ssid
                    self.wireless_devices[bssid]['channel'] = channel
                    self.wireless_devices[bssid]['last_seen'] = time.time()
                    
                    packet_info += f"📡 Beacon | SSID: {ssid} | BSSID: {bssid} | Canal: {channel} | "
                    self.save_ap_to_db(ssid, bssid, channel, timestamp)
                
                elif packet.haslayer(Dot11ProbeReq):
                    packet_type = "ProbeReq"
                    self.network_stats['probereq_count'] += 1
                    ssid = packet[Dot11ProbeReq].info.decode('utf-8', errors='ignore') if packet[Dot11ProbeReq].info else "Any"
                    self.wireless_devices[mac_src]['type'] = "Client"
                    self.wireless_devices[mac_src]['probed_ssid'] = ssid
                    self.wireless_devices[mac_src]['last_seen'] = time.time()
                    
                    packet_info += f"🔍 ProbeReq | Client: {mac_src} | Procurando: {ssid} | "
                    self.save_client_to_db(mac_src, ssid, timestamp)
                
                elif packet.haslayer(Dot11ProbeResp):
                    packet_type = "ProbeResp"
                    self.network_stats['proberesp_count'] += 1
                    ssid = packet[Dot11ProbeResp].info.decode('utf-8', errors='ignore') if packet[Dot11ProbeResp].info else "Hidden"
                    self.wireless_devices[bssid]['type'] = "AP"
                    self.wireless_devices[bssid]['ssid'] = ssid
                    self.wireless_devices[bssid]['last_seen'] = time.time()
                    
                    packet_info += f"📨 ProbeResp | AP: {bssid} | SSID: {ssid} | "
                    self.save_ap_to_db(ssid, bssid, None, timestamp)
                
                elif packet.haslayer(Dot11Deauth):
                    packet_type = "Deauth"
                    self.network_stats['deauth_count'] += 1
                    reason = packet.reason if hasattr(packet, 'reason') else "N/A"
                    packet_info += f"🚨 DEAUTH | De: {mac_src} | Para: {mac_dst} | Razão: {reason} | "
                
                elif packet.haslayer(Dot11Auth):
                    packet_type = "Auth"
                    self.network_stats['auth_count'] += 1
                    packet_info += f"🔐 Auth | De: {mac_src} | Para: {mac_dst} | "
                
                elif packet.haslayer(Dot11AssoReq):
                    packet_type = "AssoReq"
                    self.network_stats['assocreq_count'] += 1
                    packet_info += f"🤝 AssoReq | Client: {mac_src} | AP: {bssid} | "
                
                elif packet.haslayer(Dot11AssoResp):
                    packet_type = "AssoResp"
                    self.network_stats['assocresp_count'] += 1
                    packet_info += f"✅ AssoResp | AP: {bssid} | Client: {mac_src} | "
                
                else:
                    # Pacotes de dados
                    if packet.type == 2:  # Data frames
                        self.network_stats['data_count'] += 1
                        packet_type = "Data"
                        packet_info += f"📦 Data | De: {mac_src} | Para: {mac_dst} | "
                
                packet_info += f"Tipo: {packet_type} | Tamanho: {len(packet)} bytes"
                
                try:
                    self.save_packet_to_db(timestamp, mac_src, mac_dst, bssid, packet_type, len(packet), packet_info)
                except Exception as e:
                    print(f"[DB-ERRO] ao salvar pacote: {e}")
                
                self.capture_queue.put(packet_info)
                self.update_device_counts()
                
                # Atualiza estatísticas a cada 50 pacotes
                if sum(self.network_stats.values()) % 50 == 0:
                    self.show_network_stats()
                    
        except Exception as e:
            error_msg = f"\n[ERRO] Falha ao processar pacote: {str(e)}"
            self.capture_queue.put(error_msg)

    def show_network_stats(self):
        """Mostra estatísticas da rede"""
        stats_text = (
            f"\n📊 ESTATÍSTICAS DA REDE:\n"
            f"   📡 Beacons: {self.network_stats['beacon_count']}\n"
            f"   🔍 ProbeReqs: {self.network_stats['probereq_count']}\n"
            f"   📨 ProbeResps: {self.network_stats['proberesp_count']}\n"
            f"   🚨 Deauths: {self.network_stats['deauth_count']}\n"
            f"   🔐 Auths: {self.network_stats['auth_count']}\n"
            f"   🤝 AssocReqs: {self.network_stats['assocreq_count']}\n"
            f"   ✅ AssocResps: {self.network_stats['assocresp_count']}\n"
            f"   📦 Data: {self.network_stats['data_count']}\n"
        )
        self.capture_queue.put(stats_text)

    def update_device_counts(self):
        aps = sum(1 for dev in self.wireless_devices.values() if dev.get('type') == "AP")
        clients = sum(1 for dev in self.wireless_devices.values() if dev.get('type') == "Client")
        
        self.root.after(0, self.network_count.config, {'text': f"Redes detectadas: {aps}"})
        self.root.after(0, self.device_count.config, {'text': f"Dispositivos: {clients}"})
    
    def update_ui(self):
        while not self.capture_queue.empty():
            packet_info = self.capture_queue.get()
            self.packets.append(packet_info)
            self.log_area.insert(tk.END, packet_info)
            self.log_area.see(tk.END)
        
        self.root.after(100, self.update_ui)
    
    def start_capture(self):
        if not self.is_capturing:
            self.interface = self.get_selected_interface()
            if not self.interface:
                messagebox.showwarning("Aviso", "Selecione uma interface válida!")
                return
                
            try:
                self.capture_interval = int(self.interval_var.get())
                self.capture_duration = int(self.duration_var.get())
                
                if self.capture_interval < 5 or self.capture_interval > 300:
                    raise ValueError("Intervalo deve ser entre 5 e 300 segundos")
                if self.capture_duration < 5 or self.capture_duration > 60:
                    raise ValueError("Duração deve ser entre 5 e 60 segundos")
                if self.capture_duration > self.capture_interval:
                    raise ValueError("Duração não pode ser maior que o intervalo")
                    
            except ValueError as e:
                messagebox.showerror("Erro", str(e))
                return
            
            # Mostra informações da WiFi antes de iniciar
            wifi_info = (
                f"\n📶 INFORMAÇÕES DA REDE WIFI ANTES DO MONITORAMENTO:\n"
                f"   SSID: {self.current_wifi_info['ssid']}\n"
                f"   BSSID: {self.current_wifi_info['bssid']}\n"
                f"   Canal: {self.current_wifi_info['channel']}\n"
                f"   Frequência: {self.current_wifi_info['frequency']}\n"
                f"   Sinal: {self.current_wifi_info['signal_strength']}\n"
            )
            self.capture_queue.put(wifi_info)
            
            # Verifica canal não-padrão
            if self.current_wifi_info['channel'] not in [1, 6, 11] and 1 <= self.current_wifi_info['channel'] <= 13:
                self.capture_queue.put(f"⚠️  ALERTA: Canal {self.current_wifi_info['channel']} não é recomendado!\n")
                self.capture_queue.put(f"   Use canal 1, 6 ou 11 para melhor performance\n")
            
            # Mede QoS ANTES de iniciar o monitoramento (rede normal)
            self.capture_queue.put("\n📊 MEDIÇÃO QoS ANTES DO MONITORAMENTO...\n")
            self.measure_qos_before_capture()
                
            self.is_capturing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.capture_status.config(text="Monitoramento: Ativo", foreground="green")
            
            monitor_iface = self.set_monitor_mode(self.interface)
            if not monitor_iface:
                self.is_capturing = False
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
                self.capture_status.config(text="Monitoramento: Inativo", foreground="red")
                return
            
            self.interface = monitor_iface
            self.log_area.insert(tk.END, f"\nIniciando monitoramento na interface {self.interface}...\n")
            self.log_area.insert(tk.END, "⚠️  Rede temporariamente indisponível (modo monitor ativo)\n")
            
            self.capture_thread = threading.Thread(
                target=self.run_periodic_capture,
                daemon=True
            )
            self.capture_thread.start()
            
            self.update_ui()
    
    def run_periodic_capture(self):
        while self.is_capturing:
            try:
                start_time = time.time()
                self.capture_queue.put(f"\n[CAPTURA] Iniciando captura por {self.capture_duration} segundos...\n")
                
                sniff(
                    iface=self.interface,
                    prn=self.packet_handler,
                    store=0,
                    timeout=self.capture_duration,
                    monitor=True,
                    filter="type mgt or type ctl"
                )
                
                self.capture_queue.put(f"\n[CAPTURA] Captura concluída. Aguardando próximo ciclo...\n")
                
                elapsed = time.time() - start_time
                sleep_time = max(0, self.capture_interval - elapsed)
                
                for _ in range(int(sleep_time)):
                    if not self.is_capturing:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                error_msg = f"\n[ERRO GRAVE] Falha na captura: {str(e)}\n"
                self.capture_queue.put(error_msg)
                time.sleep(5)
    
    def stop_capture(self):
        if self.is_capturing:
            self.is_capturing = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.capture_status.config(text="Monitoramento: Inativo", foreground="red")
            
            # Restaura NetworkManager primeiro
            self.stop_monitor_mode(self.interface)
            
            if self.capture_thread and self.capture_thread.is_alive():
                self.capture_thread.join(timeout=1)
            
            self.log_area.insert(tk.END, "\nMonitoramento encerrado.\n")
            
            # Mede QoS APÓS parar o monitoramento (rede restaurada)
            self.log_area.insert(tk.END, "🔄 Aguardando rede se restabelecer...\n")
            self.root.after(3000, self.measure_qos_after_capture)  # Espera 3 segundos
    
    def show_network_analysis(self):
        if not self.wireless_devices:
            messagebox.showinfo("Análise", "Nenhuma rede ou dispositivo detectado ainda.")
            return
        
        aps = {k: v for k, v in self.wireless_devices.items() if v.get('type') == "AP"}
        clients = {k: v for k, v in self.wireless_devices.items() if v.get('type') == "Client"}
        
        analysis = "=== ANÁLISE DE REDES SEM FIO ===\n\n"
        analysis += f"Total de Redes (APs): {len(aps)}\n"
        analysis += f"Total de Dispositivos (Clients): {len(clients)}\n"
        
        # Informações da rede conectada
        analysis += f"\n=== REDE CONECTADA ===\n"
        analysis += f"SSID: {self.current_wifi_info['ssid']}\n"
        analysis += f"Canal: {self.current_wifi_info['channel']}\n"
        analysis += f"Sinal: {self.current_wifi_info['signal_strength']}\n"
        
        # Verifica canal
        if self.current_wifi_info['channel']:
            quality, reason = self.problem_solver.check_channel_quality(self.current_wifi_info['channel'])
            analysis += f"Qualidade do canal: {quality}\n"
            analysis += f"Detalhes: {reason}\n"
        
        analysis += f"\n=== MÉTRICAS QoS ===\n"
        analysis += f"Latência: {self.qos_metrics['latency']}ms\n"
        analysis += f"Jitter: {self.qos_metrics['jitter']}ms\n"
        analysis += f"Perda de Pacotes: {self.qos_metrics['packet_loss']}%\n"
        analysis += f"Última Atualização: {self.qos_metrics['last_update']}\n"
        analysis += f"Status: {self.qos_metrics['status']}\n"
        analysis += f"Total de Medições: {self.qos_measurement_count}\n\n"
        
        analysis += "=== REDES DETECTADAS ===\n"
        for bssid, info in aps.items():
            ssid = info.get('ssid', 'Desconhecido')
            channel = info.get('channel', '?')
            last_seen = datetime.datetime.fromtimestamp(info.get('last_seen', 0)).strftime('%H:%M:%S')
            analysis += f"SSID: {ssid}\nBSSID: {bssid}\nCanal: {channel}\nÚltimo sinal: {last_seen}\n\n"
        
        analysis_window = tk.Toplevel(self.root)
        analysis_window.title("Análise de Redes Sem Fio")
        analysis_window.geometry("700x500")
        
        text_area = scrolledtext.ScrolledText(
            analysis_window,
            wrap=tk.WORD,
            font=('Consolas', 9)
        )
        text_area.pack(fill=tk.BOTH, expand=True)
        text_area.insert(tk.END, analysis)
        text_area.config(state=tk.DISABLED)
    
    def clear_all(self):
        self.packets = []
        self.wireless_devices.clear()
        self.network_stats.clear()
        self.qos_metrics.update({'latency': 0, 'jitter': 0, 'packet_loss': 0, 'last_update': "Nunca", 'status': "Não medito"})
        self.qos_measurement_count = 0
        self.last_diagnosis = []
        self.last_qos_before_capture = None
        self.log_area.delete(1.0, tk.END)
        self.log_area.insert(tk.END, "Todos os dados foram limpos. Pronto para novo monitoramento.\n")
        self.network_count.config(text="Redes detectadas: 0")
        self.device_count.config(text="Dispositivos: 0")
        self.qos_status.config(text="QoS: Não medito")
        
        # Para simulação se estiver ativa
        if self.simulator.simulation_active:
            self.stop_simulation()

if __name__ == "__main__":
    root = tk.Tk()
    app = WirelessMonitorApp(root)
    root.mainloop()
