# -*- coding: utf-8 -*-


import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from aresitos.utils.detector_red import DetectorRed
# Importar el gestor de sudo de ARESITOS
from aresitos.utils.sudo_manager import get_sudo_manager




class VistaEscaneo(tk.Frame):
    def ejecutar_comando_entry(self, event=None):
        """Ejecuta el comando ingresado en la terminal, mostrando el resultado en la UI. Validar seguridad antes de ejecutar comandos reales."""
        comando = self.comando_entry.get()
        self._actualizar_terminal_seguro(f"$ {comando}\n")
        # Aquí puedes ejecutar el comando real si lo deseas, validando seguridad
        self.comando_entry.delete(0, tk.END)
    def _log_terminal(self, mensaje, modulo="ESCANEADOR", nivel="INFO"):
        """Log al terminal integrado de manera segura."""
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] [{modulo}] [{nivel}] {mensaje}\n"
        self._actualizar_terminal_seguro(formatted_msg)

    def _mostrar_resultados_escaneo_kali(self, resultado):
        """Mostrar solo resultados técnicos útiles del escaneo."""
        try:
            fases = resultado.get("fases", {})
            # Puertos abiertos
            masscan = fases.get("masscan", {})
            puertos = masscan.get("puertos_abiertos", [])
            if puertos:
                self._actualizar_texto_seguro("Puertos abiertos detectados:\n")
                for p in puertos:
                    self._actualizar_texto_seguro(f"  - {p['ip']}:{p['puerto']}/{p['protocolo']}\n")
            # Servicios detectados
            nmap = fases.get("nmap", {})
            servicios = nmap.get("servicios", [])
            if servicios:
                for p in puertos:
                    objetivo_puerto = f"{p['ip']}:{p['puerto']}"
                    # nuclei debe estar definido en el contexto real
                    # vulns = nuclei.get("vulnerabilidades", [])
                    # if vulns:
                    #     self._actualizar_texto_seguro(f"Vulnerabilidades en {objetivo_puerto}:\n")
                    #     for v in vulns[:5]:
                    #         self._actualizar_texto_seguro(f"  - {v}\n")
                    #     if len(vulns) > 5:
                    #         self._actualizar_texto_seguro(f"  ... y {len(vulns) - 5} vulnerabilidades más\n")
        except Exception as e:
            self._actualizar_texto_seguro(f"Error mostrando resultados: {str(e)}\n")
    def set_controlador(self, controlador):
        self.controlador = controlador
    @staticmethod
    def _get_base_dir():
        import os
        from pathlib import Path
        return Path(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
    def actualizar_bases_datos(self):
        """Actualizar todas las bases de datos usadas por ARESITOS (vulnerabilidades, wordlists, diccionarios)."""
        import os
        import json
        from tkinter import messagebox
        self.progress_label.config(text="Actualizando bases de datos...")
        self.progress_bar['value'] = 0
        errores = []
        try:
            # Recargar wordlists
            try:
                from aresitos.modelo.modelo_wordlists_gestor import ModeloGestorWordlists
                gestor_wordlists = ModeloGestorWordlists()
                gestor_wordlists._cargar_wordlists_desde_data()
                self.progress_bar['value'] = 33
            except Exception as e:
                errores.append(f"Wordlists: {e}")

            # Recargar diccionarios
            try:
                from aresitos.modelo.modelo_diccionarios import ModeloGestorDiccionarios
                gestor_diccionarios = ModeloGestorDiccionarios()
                gestor_diccionarios._cargar_diccionarios_desde_data()
                self.progress_bar['value'] = 66
            except Exception as e:
                errores.append(f"Diccionarios: {e}")

            # Recargar base de vulnerabilidades
            try:
                base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "vulnerability_database.json"))
                if os.path.exists(base_path):
                    with open(base_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    total = data.get('metadatos', {}).get('total_vulnerabilidades', '?')
                else:
                    raise FileNotFoundError("vulnerability_database.json no encontrada")
                self.progress_bar['value'] = 100
            except Exception as e:
                errores.append(f"Vulnerabilidades: {e}")

            if errores:
                self.progress_label.config(text="Actualización completada con errores")
                messagebox.showwarning("Actualizar Bases", "Actualización completada con errores:\n" + "\n".join(errores))
            else:
                self.progress_label.config(text="Bases de datos actualizadas correctamente")
                messagebox.showinfo("Actualizar Bases", "¡Todas las bases de datos han sido actualizadas correctamente!")
        except Exception as e:
            self.progress_label.config(text="Error actualizando bases de datos")
            messagebox.showerror("Actualizar Bases", f"Error crítico actualizando bases: {e}")
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.controlador = None
        from aresitos.utils.logger_aresitos import LoggerAresitos
        self.logger = LoggerAresitos.get_instance()
        self.proceso_activo = False
        # Colores estándar
        self.colors = {
            'bg_primary': '#f0f0f0',
            'bg_secondary': '#ffffff',
            'fg_primary': '#000000',
            'fg_secondary': '#666666',
            'fg_accent': '#ff6633',
            'button_bg': '#007acc',
            'button_fg': '#ffffff',
            'danger': '#d32f2f',
            'info': '#1976d2',
            'warning': '#ffaa00'
        }
        try:
            from aresitos.vista.burp_theme import burp_theme
            if burp_theme:
                self.colors.update({
                    'bg_primary': burp_theme.get_color('bg_primary'),
                    'bg_secondary': burp_theme.get_color('bg_secondary'),
                    'fg_primary': burp_theme.get_color('fg_primary'),
                    'fg_secondary': burp_theme.get_color('fg_secondary'),
                    'fg_accent': burp_theme.get_color('fg_accent'),
                    'button_bg': burp_theme.get_color('button_bg'),
                    'button_fg': burp_theme.get_color('button_fg'),
                })
        except Exception:
            pass

        # Frame principal vertical
        self.main_frame = tk.Frame(self, bg=self.colors['bg_primary'])
        self.main_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # --- 1. Botones principales (arriba, horizontal) ---
        self.top_buttons_frame = tk.Frame(self.main_frame, bg=self.colors['bg_primary'])
        self.top_buttons_frame.pack(fill="x", pady=(8, 2))

        self.btn_escanear = ttk.Button(
            self.top_buttons_frame, text="Escanear Red",
            command=self.ejecutar_escaneo,
            style='Burp.TButton', width=16
        )
        self.btn_escanear.pack(side="left", padx=(8, 8), pady=4)

        # Entrada para agregar IP manualmente a cuarentena
        self.entry_ip_cuarentena = tk.Entry(self.top_buttons_frame, font=("Arial", 11), width=18)
        self.entry_ip_cuarentena.pack(side="left", padx=(8, 2), pady=4)
        self.btn_agregar_ip_cuarentena = ttk.Button(
            self.top_buttons_frame, text="Agregar IP a cuarentena",
            command=self.agregar_ip_manual_a_cuarentena,
            style='Burp.TButton', width=16
        )
        self.btn_agregar_ip_cuarentena.pack(side="left", padx=2, pady=4)

        self.btn_actualizar_bases = ttk.Button(
            self.top_buttons_frame, text="Actualizar Bases",
            command=self.actualizar_bases_datos,
            style='Burp.TButton', width=16
        )
        self.btn_actualizar_bases.pack(side="left", padx=8, pady=4)

        self.btn_cancelar_escaneo = ttk.Button(
            self.top_buttons_frame, text="Cancelar",
            state="disabled",
            style='Burp.TButton', width=16
        )
        self.btn_cancelar_escaneo.pack(side="left", padx=8, pady=4)

        # --- 2. Barra de progreso y estado ---
        self.progress_frame = tk.Frame(self.main_frame, bg=self.colors['bg_primary'])
        self.progress_frame.pack(fill="x", pady=(0, 8))
        self.progress_label = tk.Label(self.progress_frame, text="Estado: Listo",
                                       bg=self.colors['bg_primary'],
                                       fg=self.colors['fg_primary'],
                                       font=('Arial', 9))
        self.progress_label.pack(side="left", padx=(8, 10))
        self.progress_bar = ttk.Progressbar(self.progress_frame, mode='determinate', length=200)
        self.progress_bar.pack(side="left")

        # --- 3. Área de resultados ---
        self.text_resultados = scrolledtext.ScrolledText(self.main_frame, height=18,
                                                         bg=self.colors['bg_secondary'],
                                                         fg=self.colors['fg_primary'],
                                                         font=('Consolas', 10),
                                                         insertbackground=self.colors['fg_accent'],
                                                         selectbackground=self.colors['fg_accent'],
                                                         relief='flat', bd=1)
        self.text_resultados.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        # --- 4. Terminal integrado (estilo SIEM/Monitoreo) ---
        self.terminal_frame = tk.LabelFrame(
            self.main_frame,
            text="Terminal ARESITOS - Escaneador",
            bg="#232629",
            fg="#ffb86c",
            font=("Arial", 10, "bold")
        )
        self.terminal_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Controles de terminal (estilo SIEM)
        controles_frame = tk.Frame(self.terminal_frame, bg="#232629")
        controles_frame.pack(fill="x", padx=5, pady=2)

        btn_limpiar = tk.Button(
            controles_frame,
            text="LIMPIAR",
            command=self.limpiar_terminal_escaneo,
            bg="#ffaa00",
            fg='white',
            font=("Arial", 8, "bold"),
            height=1
        )
        btn_limpiar.pack(side="left", padx=2, fill="x", expand=True)

        btn_logs = tk.Button(
            controles_frame,
            text="VER LOGS",
            command=self.ver_logs,
            bg="#007acc",
            fg='white',
            font=("Arial", 8, "bold"),
            height=1
        )
        btn_logs.pack(side="left", padx=2, fill="x", expand=True)

        # Área de terminal (estilo SIEM)
        self.terminal_output = scrolledtext.ScrolledText(
            self.terminal_frame,
            height=6,
            bg='#000000',
            fg='#00ff00',
            font=("Consolas", 8),
            insertbackground='#00ff00',
            selectbackground='#333333'
        )
        self.terminal_output.pack(fill="both", expand=True, padx=5, pady=5)

        # Entrada de comandos (estilo SIEM)
        entrada_frame = tk.Frame(self.terminal_frame, bg='#1e1e1e')
        entrada_frame.pack(fill="x", padx=5, pady=2)
        tk.Label(entrada_frame, text="COMANDO:", bg='#1e1e1e', fg='#00ff00', font=("Arial", 9, "bold")).pack(side="left", padx=(0, 5))
        self.comando_entry = tk.Entry(entrada_frame, bg='#000000', fg='#00ff00', font=("Consolas", 9), insertbackground='#00ff00')
        self.comando_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.comando_entry.bind("<Return>", self.ejecutar_comando_entry)
        ejecutar_btn = tk.Button(entrada_frame, text="EJECUTAR", command=self.ejecutar_comando_entry, bg='#2d5aa0', fg='white', font=("Arial", 8, "bold"))
        ejecutar_btn.pack(side="right")

        # Mensaje inicial estilo SIEM
        self._actualizar_terminal_seguro("="*60 + "\n")
        self._actualizar_terminal_seguro("Terminal ARESITOS - Escaneador v2.0\n")
        import datetime
        self._actualizar_terminal_seguro(f"Iniciado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self._actualizar_terminal_seguro("Sistema: Kali Linux - Network & Vulnerability Scanner\n")
        self._actualizar_terminal_seguro("="*60 + "\n")
        self._actualizar_terminal_seguro("LOG Escaneo en tiempo real\n\n")

    def ejecutar_escaneo(self):
        """Ejecutar escaneo del sistema."""
        if self.proceso_activo:
            return
            
        if not self.controlador:
            messagebox.showerror("Error", "No hay controlador de escaneo configurado")
            return
        
        # Limpiar resultados anteriores
        self.text_resultados.delete('1.0', tk.END)
        self.text_resultados.insert(tk.END, "Iniciando escaneo...\n\n")
        
        # Inicializar barra de progreso
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Estado: Iniciando escaneo...")
        
        # Configurar UI para escaneo
        self.proceso_activo = True
        self.btn_escanear.config(state="disabled")
        self.btn_cancelar_escaneo.config(state="normal")
        # Ejecutar escaneo en thread separado
        self.thread_escaneo = threading.Thread(target=self._ejecutar_escaneo_async)
        self.thread_escaneo.daemon = True
        self.thread_escaneo.start()
    def _ejecutar_escaneo_async(self):
        """Ejecutar escaneo completo del sistema usando el escaneador avanzado Kali 2025."""
        import subprocess
        from aresitos.utils.detector_red import DetectorRed
        self._actualizar_texto_seguro("HERRAMIENTAS: masscan, nmap, nuclei, gobuster, ffuf\n\n")
        # Determinar objetivos: IP, red local, DNS
        objetivos = []
        dns_detectado = "No detectado"
        try:
            ip_local, red_cidr = DetectorRed.obtener_objetivos_escaneo()
            dns_detectado = DetectorRed.obtener_dns()
            objetivos = [ip_local, red_cidr]
            if dns_detectado and dns_detectado != "No detectado":
                objetivos.append(dns_detectado)
            if not objetivos:
                objetivos = ["127.0.0.1"]
        except Exception:
            objetivos = ["127.0.0.1"]
        # Mostrar objetivos y DNS juntos
        try:
            self._actualizar_texto_seguro(f"Objetivos escaneados: {', '.join(objetivos)}\nDNS detectado: {dns_detectado}\n")
        except Exception:
            pass
        # Ejecutar escaneo integral para cada objetivo
        for objetivo in objetivos:
            resultado = self._escaneo_integral_kali(objetivo)
            self.ultimos_resultados = resultado
            self._mostrar_resultados_escaneo_kali(resultado)
    def agregar_ip_manual_a_cuarentena(self):
        """Permite al usuario agregar manualmente una IP, vulnerabilidad, DNS, etc. a cuarentena desde la UI."""
        from tkinter import messagebox
        ip_manual = self.entry_ip_cuarentena.get().strip()
        controlador_cuarentena = getattr(self.controlador, 'controlador_cuarentena', None)
        if not ip_manual and (not hasattr(self, 'ultimos_resultados') or not self.ultimos_resultados):
            messagebox.showwarning("Cuarentena", "Debes ingresar una IP o realizar un escaneo para poner elementos en cuarentena.")
            return
        if controlador_cuarentena:
            # Si hay IP manual, ponerla en cuarentena
            if ip_manual:
                controlador_cuarentena.poner_ip_en_cuarentena(ip_manual, tipo_amenaza="manual", razon="Agregada manualmente por el usuario")
                messagebox.showinfo("Cuarentena", f"IP/DNS/vulnerabilidad '{ip_manual}' puesta en cuarentena correctamente.")
                self.entry_ip_cuarentena.delete(0, tk.END)
            # Si hay resultados de escaneo, poner IPs, DNS y vulnerabilidades en cuarentena
            if hasattr(self, 'ultimos_resultados') and self.ultimos_resultados:
                ips_cuarentena = []
                dns_cuarentena = self.ultimos_resultados.get('dns', None)
                vulns_cuarentena = []
                fases = self.ultimos_resultados.get('fases', {})
                for fase in fases.values():
                    if 'puertos' in fase:
                        for p in fase['puertos']:
                            if 'ip' in p:
                                ips_cuarentena.append(p['ip'])
                    if 'vulnerabilidades' in fase:
                        vulns_cuarentena.extend(fase['vulnerabilidades'])
                elementos = set(ips_cuarentena)
                if dns_cuarentena:
                    elementos.add(dns_cuarentena)
                elementos.update(vulns_cuarentena)
                if elementos:
                    for elem in elementos:
                        controlador_cuarentena.poner_ip_en_cuarentena(elem, tipo_amenaza="escaneo", razon="Detectado en escaneo")
                    messagebox.showinfo("Cuarentena", f"Elementos puestos en cuarentena: {', '.join(elementos)}")
                else:
                    messagebox.showinfo("Cuarentena", "No se detectaron elementos para poner en cuarentena.")
        else:
            messagebox.showerror("Cuarentena", "No se encontró el controlador de cuarentena en el controlador principal.")
        self._finalizar_escaneo()

    def _finalizar_escaneo(self):
        """Finalizar el proceso de escaneo."""
        self.proceso_activo = False
        self.btn_escanear.config(state="normal")
        self.btn_cancelar_escaneo.config(state="disabled")
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Estado: Listo")
        self.thread_escaneo = None
        # Enviar resultados a Reportes automáticamente
        try:
            from aresitos.vista.vista_reportes import VistaReportes
            vista_reportes = None
            if hasattr(self.master, 'vista_reportes'):
                vista_reportes = getattr(self.master, 'vista_reportes', None)
            else:
                vistas = getattr(self.master, 'vistas', None)
                if vistas and hasattr(vistas, 'get'):
                    vista_reportes = vistas.get('reportes', None)
            # Solo enviar datos si el método existe
            if vista_reportes and hasattr(self, 'obtener_datos_para_reporte'):
                try:
                    datos = self.obtener_datos_para_reporte()
                    vista_reportes.set_datos_modulo('escaneo', datos)
                except Exception:
                    pass
        except Exception:
            pass
    def obtener_datos_para_reporte(self):
        """Devuelve los datos relevantes del último escaneo para el módulo de reportes."""
        # Puedes personalizar la estructura según lo que quieras reportar
        return {
            "resultados": getattr(self, "ultimos_resultados", []),
            "timestamp": getattr(self, "ultimo_timestamp", "")
        }

    def cancelar_escaneo(self):
        """Cancela el escaneo en curso deteniendo el hilo si está activo."""
        import threading
        if hasattr(self, 'thread_escaneo') and self.thread_escaneo and self.thread_escaneo.is_alive():
            # No se puede detener un hilo de Python de forma segura, pero se puede usar una bandera
            self.proceso_activo = False
            self.progress_label.config(text="Estado: Escaneo cancelado")
            self.btn_escanear.config(state="normal")
            self.btn_cancelar_escaneo.config(state="disabled")
            self._actualizar_texto_seguro("Escaneo cancelado por el usuario.\n")
        else:
            self._actualizar_texto_seguro("No hay escaneo activo para cancelar.\n")

    def configurar_tipo_escaneo(self, tipo_escaneo="integral"):
        """Configurar el tipo de escaneo a realizar."""
        tipos_validos = {
            "integral": "Escaneo integral básico con herramientas nativas",
            "avanzado": "Escaneo avanzado con múltiples herramientas",
            "red": "Escaneo completo de red local",
            "rapido": "Escaneo rápido de puertos comunes",
            "profundo": "Escaneo profundo con detección de vulnerabilidades"
        }
        if tipo_escaneo not in tipos_validos:
            self._actualizar_texto_seguro(f"Tipo de escaneo inválido: {tipo_escaneo}\n")
            self._actualizar_texto_seguro("Tipos válidos:\n")
            for tipo, desc in tipos_validos.items():
                self._actualizar_texto_seguro(f"  - {tipo}: {desc}\n")
            return False
        self.tipo_escaneo_actual = tipo_escaneo
        self._actualizar_texto_seguro(f"Tipo de escaneo configurado: {tipos_validos[tipo_escaneo]}\n")
        return True

    def ejecutar_escaneo_configurado(self, objetivo):
        """Ejecutar escaneo según el tipo configurado."""
        tipo = getattr(self, 'tipo_escaneo_actual', 'integral')
        self._actualizar_texto_seguro(f"Ejecutando escaneo tipo '{tipo}' para objetivo: {objetivo}\n")
        try:
            if tipo == "integral":
                return self._escaneo_integral_kali(objetivo)
            elif tipo == "avanzado":
                return self._escaneo_avanzado_multiherramienta(objetivo)
            elif tipo == "red":
                # Si el objetivo parece ser una IP, convertir a rango de red
                if "/" not in objetivo and self._validar_ip(objetivo):
                    partes = objetivo.split('.')
                    if len(partes) == 4:
                        rango_red = f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"
                    else:
                        rango_red = objetivo
                else:
                    rango_red = objetivo
                return self._escaneo_red_completa(rango_red)
            elif tipo == "rapido":
                return self._escaneo_rapido_puertos(objetivo)
            elif tipo == "profundo":
                return self._escaneo_profundo_vulnerabilidades(objetivo)
            else:
                return self._escaneo_integral_kali(objetivo)
        except Exception as e:
            error_msg = f"Error en escaneo configurado: {str(e)}"
            self._actualizar_texto_seguro(error_msg + "\n")
            return {"exito": False, "error": error_msg}

    def _escaneo_integral_kali(self, objetivo):
        """Escaneo integral usando herramientas nativas de Kali Linux, mostrando comandos y progreso en tiempo real."""
        try:
            from aresitos.modelo.modelo_escaneador import EscaneadorKali2025
            escaneador = EscaneadorKali2025()
            def terminal_callback(msg):
                self._actualizar_terminal_seguro(msg)
            def progreso_callback(valor):
                self.progress_bar['value'] = valor
                self.progress_label.config(text=f"Progreso: {valor}%")
                self.update_idletasks()
            self._actualizar_texto_seguro(f"\nFASE 1: Escaneo de puertos con masscan...\n")
            resultado = escaneador.escaneo_completo_kali2025(
                objetivo,
                callback_terminal=terminal_callback,
                callback_progreso=progreso_callback
            )
            self._mostrar_resultados_escaneo_kali(resultado)
            self.progress_bar['value'] = 100
            self.progress_label.config(text="Estado: Escaneo completado")
            return resultado
        except Exception as e:
            self._actualizar_texto_seguro(f"Error en escaneo integral: {str(e)}\n")
            return {"exito": False, "error": str(e)}

    def _escaneo_avanzado_multiherramienta(self, objetivo):
        """Escaneo avanzado usando múltiples herramientas profesionales."""
        import subprocess
        resultados = {"herramientas": {}}
        herramientas = [
            ("gobuster", ["gobuster", "dir", "-u", f"http://{objetivo}", "-w", "/usr/share/wordlists/dirb/common.txt"]),
            ("nuclei", ["nuclei", "-u", objetivo]),
            ("ffuf", ["ffuf", "-u", f"http://{objetivo}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt"])
        ]
        for nombre, cmd in herramientas:
            try:
                resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                resultados["herramientas"][nombre] = resultado.stdout if resultado.returncode == 0 else resultado.stderr
            except Exception as e:
                resultados["herramientas"][nombre] = f"Error: {str(e)}"
        self._actualizar_texto_seguro(f"Escaneo avanzado completado.\n")
        return resultados

    def _escaneo_red_completa(self, rango_red=None):
        """Escaneo completo de una red local."""
        import subprocess
        self._actualizar_texto_seguro(f"Escaneo de red: {rango_red}\n")
        hosts_activos = []
        try:
            nmap_cmd = ["nmap", "-sn", rango_red]
            resultado_red = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=60)
            if resultado_red.returncode == 0:
                for linea in resultado_red.stdout.split("\n"):
                    if "Nmap scan report for" in linea:
                        ip = linea.split()[-1]
                        hosts_activos.append(ip)
            self._actualizar_texto_seguro(f"HOSTS ACTIVOS: {len(hosts_activos)}\n")
        except Exception as e:
            self._actualizar_texto_seguro(f"Error en escaneo de red: {str(e)}\n")
        return {"exito": True, "resultado": {"hosts": hosts_activos}}

    def _escaneo_rapido_puertos(self, objetivo):
        """Escaneo rápido de puertos más comunes."""
        import subprocess
        puertos_comunes = "22,23,53,80,135,139,443,445,993,995,1723,3389,5900,8080"
        self._actualizar_texto_seguro(f"Escaneo rápido de puertos en {objetivo}\n")
        try:
            nmap_cmd = ["nmap", "-sS", "-T4", objetivo, "-p", puertos_comunes]
            resultado_nmap = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=60)
            puertos_abiertos = []
            if resultado_nmap.returncode == 0 and resultado_nmap.stdout.strip():
                for linea in resultado_nmap.stdout.split("\n"):
                    if "open" in linea:
                        puertos_abiertos.append(linea.strip())
            self._actualizar_texto_seguro(f"Puertos abiertos: {len(puertos_abiertos)}\n")
        except Exception as e:
            self._actualizar_texto_seguro(f"Error en escaneo rápido: {str(e)}\n")
        return {"exito": True, "resultado": {"puertos": puertos_abiertos}}

    def _escaneo_profundo_vulnerabilidades(self, objetivo):
        """Escaneo profundo enfocado en vulnerabilidades y seguridad avanzada solo con herramientas ya presentes y comandos nativos."""
        import subprocess
        self._actualizar_texto_seguro(f"Escaneo profundo de vulnerabilidades en {objetivo}\n")
        resultado = {}
        try:
            nuclei_cmd = ["nuclei", "-u", objetivo]
            resultado_nuclei = subprocess.run(nuclei_cmd, capture_output=True, text=True, timeout=120)
            vulnerabilidades = []
            if resultado_nuclei.returncode == 0 and resultado_nuclei.stdout.strip():
                for linea in resultado_nuclei.stdout.split("\n"):
                    if linea.strip():
                        vulnerabilidades.append(linea.strip())
            self._actualizar_texto_seguro(f"Vulnerabilidades encontradas: {len(vulnerabilidades)}\n")
            resultado["vulnerabilidades"] = vulnerabilidades
        except Exception as e:
            self._actualizar_texto_seguro(f"Error en escaneo profundo: {str(e)}\n")
            resultado["error"] = str(e)
        return {"exito": True, "resultado": resultado}

    def _validar_ip(self, ip_str):
        """Validar formato de dirección IP."""
        import ipaddress
        try:
            ipaddress.ip_address(ip_str)
            return True
        except Exception:
            return False

    def limpiar_terminal_escaneo(self):
        """Limpiar terminal Escaneo manteniendo cabecera."""
        self.terminal_output.delete('1.0', tk.END)
        self._actualizar_terminal_seguro("="*60 + "\n")
        self._actualizar_terminal_seguro("Terminal ARESITOS - Escaneador v2.0\n")
        import datetime
        self._actualizar_terminal_seguro(f"Iniciado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self._actualizar_terminal_seguro("Sistema: Kali Linux - Network & Vulnerability Scanner\n")
        self._actualizar_terminal_seguro("="*60 + "\n")
        self._actualizar_terminal_seguro("LOG Escaneo en tiempo real\n\n")

    def _actualizar_terminal_seguro(self, texto):
        self.terminal_output.insert(tk.END, texto)
        self.terminal_output.see(tk.END)

    def _actualizar_texto_seguro(self, texto):
        self.text_resultados.insert(tk.END, texto)
        self.text_resultados.see(tk.END)

    def ver_logs(self):
        """Ver logs almacenados de escaneos y verificaciones."""
        if not self.controlador:
            self._log_terminal("Error: No hay controlador configurado", "LOGS", "ERROR")
            return
        self.text_resultados.delete(1.0, tk.END)
        self.text_resultados.insert(tk.END, "=== LOGS DE ESCANEO Y VERIFICACION ===\n\n")
        self._log_terminal("Consultando logs almacenados", "LOGS", "INFO")
        try:
            logs = self.controlador.obtener_logs_escaneo()
            if logs:
                self.text_resultados.insert(tk.END, "=== LOGS DEL CONTROLADOR ===\n")
                for linea in logs:
                    self.text_resultados.insert(tk.END, f"{linea}\n")
                self.text_resultados.insert(tk.END, "\n")
            else:
                self.text_resultados.insert(tk.END, "No se encontraron logs almacenados.\n")
        except Exception as e:
            self.text_resultados.insert(tk.END, f"Error obteniendo logs: {str(e)}\n")
            self._log_terminal(f"Error obteniendo logs: {str(e)}", "LOGS", "ERROR")


