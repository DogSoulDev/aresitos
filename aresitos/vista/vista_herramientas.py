# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import logging

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaHerramientas(tk.Frame):
    """Vista para herramientas del sistema"""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.controlador = None
        self.proceso_activo = False
        self.logger = logging.getLogger(__name__)
        
        # Configurar tema
        if BURP_THEME_AVAILABLE and burp_theme:
            self.theme = burp_theme
            self.configure(bg=burp_theme.get_color('bg_primary'))
            self.colors = {
                'bg_primary': burp_theme.get_color('bg_primary'),
                'bg_secondary': burp_theme.get_color('bg_secondary'), 
                'fg_primary': burp_theme.get_color('fg_primary'),
                'fg_accent': burp_theme.get_color('fg_accent'),
                'button_bg': burp_theme.get_color('button_bg'),
                'success': burp_theme.get_color('success')
            }
        else:
            self.colors = {
                'bg_primary': '#f0f0f0',
                'bg_secondary': '#ffffff',
                'fg_primary': '#000000',
                'fg_accent': '#ff6633',
                'button_bg': '#007acc',
                'success': '#00aa00'
            }
            self.configure(bg=self.colors['bg_primary'])
        
        self.configurar_ui()
    
    def configurar_ui(self):
        """Configura la interfaz de usuario completa"""
        # Frame principal
        self.frame_principal = tk.Frame(self, bg=self.colors['bg_primary'])
        self.frame_principal.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Título
        titulo = tk.Label(
            self.frame_principal,
            text="Gestión de Herramientas del Sistema",
            font=("Arial", 16, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['fg_accent']
        )
        titulo.pack(pady=(0, 20))
        
        # Frame de botones
        botones_frame = tk.Frame(self.frame_principal, bg=self.colors['bg_primary'])
        botones_frame.pack(fill="x", pady=(0, 20))
        
        # Botón verificar sistema
        self.btn_verificar_sistema = tk.Button(
            botones_frame,
            text="Verificar Sistema",
            command=self.verificar_sistema,
            bg=self.colors['button_bg'],
            fg='white',
            font=('Arial', 11, 'bold'),
            relief='flat',
            padx=20,
            pady=8,
            cursor='hand2'
        )
        self.btn_verificar_sistema.pack(side="left", padx=(0, 10))
        
        # Botón listar herramientas
        self.btn_listar_herramientas = tk.Button(
            botones_frame,
            text="Listar Herramientas",
            command=self.listar_herramientas,
            bg=self.colors['button_bg'],
            fg='white',
            font=('Arial', 11, 'bold'),
            relief='flat',
            padx=20,
            pady=8,
            cursor='hand2'
        )
        self.btn_listar_herramientas.pack(side="left", padx=(0, 10))
        
        # Botón verificar permisos
        self.btn_verificar_permisos = tk.Button(
            botones_frame,
            text="Verificar Permisos",
            command=self.verificar_permisos,
            bg=self.colors['button_bg'],
            fg='white',
            font=('Arial', 11, 'bold'),
            relief='flat',
            padx=20,
            pady=8,
            cursor='hand2'
        )
        self.btn_verificar_permisos.pack(side="left", padx=(0, 10))
        
        # Botón actualizar sistema
        self.btn_actualizar = tk.Button(
            botones_frame,
            text="Actualizar Sistema",
            command=self.actualizar_sistema,
            bg=self.colors['success'],
            fg='white',
            font=('Arial', 11, 'bold'),
            relief='flat',
            padx=20,
            pady=8,
            cursor='hand2'
        )
        self.btn_actualizar.pack(side="right")
        
        # Área de resultados
        self.text_resultados = scrolledtext.ScrolledText(
            self.frame_principal,
            height=20,
            bg=self.colors['bg_secondary'],
            fg=self.colors['fg_primary'],
            font=('Consolas', 10),
            insertbackground=self.colors['fg_accent'],
            relief='flat',
            bd=1
        )
        self.text_resultados.pack(fill="both", expand=True)
        
        # Mensaje inicial
        self.text_resultados.insert(tk.END, 
            "Gestión de Herramientas del Sistema - ARESITOS\n" +
            "=" * 50 + "\n\n" +
            "Seleccione una opción para comenzar:\n" +
            "• Verificar Sistema: Información general del sistema\n" +
            "• Listar Herramientas: Herramientas disponibles\n" +
            "• Verificar Permisos: Estado de permisos\n" +
            "• Actualizar Sistema: Actualizar paquetes\n\n"
        )
    
    def set_controlador(self, controlador):
        """Establece el controlador para esta vista"""
        self.controlador = controlador
        if controlador:
            self.logger.info("Controlador establecido en VistaHerramientas")
    
    def verificar_sistema(self):
        """Verificar información del sistema"""
        if self.proceso_activo:
            return
        
        self.proceso_activo = True
        self._deshabilitar_botones()
        self.text_resultados.delete(1.0, tk.END)
        
        # Ejecutar en thread separado
        thread = threading.Thread(target=self._verificar_sistema_async)
        thread.daemon = True
        thread.start()
    
    def _verificar_sistema_async(self):
        """Verificación asíncrona del sistema"""
        try:
            self.after(0, self._actualizar_texto, "Verificando información del sistema...\n\n")
            
            # Información básica del sistema
            comandos = [
                ('Sistema Operativo', ['uname', '-a']),
                ('Distribución', ['lsb_release', '-a']),
                ('Usuario Actual', ['whoami']),
                ('Directorio Actual', ['pwd']),
                ('Memoria', ['free', '-h']),
                ('Espacio en Disco', ['df', '-h']),
                ('Procesos Python', ['pgrep', '-f', 'python'])
            ]
            
            for descripcion, comando in comandos:
                try:
                    result = subprocess.run(comando, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        self.after(0, self._actualizar_texto, f"{descripcion}:\n{result.stdout}\n")
                    else:
                        self.after(0, self._actualizar_texto, f"{descripcion}: Error - {result.stderr}\n")
                except subprocess.TimeoutExpired:
                    self.after(0, self._actualizar_texto, f"{descripcion}: Timeout\n")
                except FileNotFoundError:
                    self.after(0, self._actualizar_texto, f"{descripcion}: Comando no encontrado\n")
                except Exception as e:
                    self.after(0, self._actualizar_texto, f"{descripcion}: Error - {e}\n")
                
                self.after(0, self._actualizar_texto, "\n")
                
        except Exception as e:
            self.after(0, self._actualizar_texto, f"Error durante la verificación: {e}\n")
        finally:
            self.after(0, self._finalizar_proceso)
    
    def listar_herramientas(self):
        """Listar herramientas disponibles"""
        if self.proceso_activo:
            return
        
        self.proceso_activo = True
        self._deshabilitar_botones()
        self.text_resultados.delete(1.0, tk.END)
        
        # Ejecutar en thread separado
        thread = threading.Thread(target=self._listar_herramientas_async)
        thread.daemon = True
        thread.start()
    
    def _listar_herramientas_async(self):
        """Listado asíncrono de herramientas"""
        try:
            self.after(0, self._actualizar_texto, "Listando herramientas disponibles...\n\n")
            
            # Lista de herramientas a verificar
            herramientas = [
                'python3', 'python', 'pip3', 'pip',
                'git', 'curl', 'wget', 'ssh', 'scp',
                'nmap', 'netcat', 'nc', 'masscan',
                'hashcat', 'john', 'hydra',
                'clamav', 'chkrootkit', 'rkhunter',
                'grep', 'awk', 'sed', 'find'
            ]
            
            herramientas_encontradas = []
            herramientas_faltantes = []
            
            for herramienta in herramientas:
                try:
                    result = subprocess.run(['which', herramienta], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        path = result.stdout.strip()
                        herramientas_encontradas.append((herramienta, path))
                        self.after(0, self._actualizar_texto, f"✓ {herramienta} -> {path}\n")
                    else:
                        herramientas_faltantes.append(herramienta)
                        self.after(0, self._actualizar_texto, f"✗ {herramienta} - No encontrada\n")
                except Exception:
                    herramientas_faltantes.append(herramienta)
                    self.after(0, self._actualizar_texto, f"✗ {herramienta} - Error al verificar\n")
            
            # Resumen
            self.after(0, self._actualizar_texto, f"\n{'='*50}\n")
            self.after(0, self._actualizar_texto, f"RESUMEN:\n")
            self.after(0, self._actualizar_texto, f"Herramientas encontradas: {len(herramientas_encontradas)}\n")
            self.after(0, self._actualizar_texto, f"Herramientas faltantes: {len(herramientas_faltantes)}\n")
            
            if herramientas_faltantes:
                self.after(0, self._actualizar_texto, f"\nFaltantes: {', '.join(herramientas_faltantes)}\n")
                
        except Exception as e:
            self.after(0, self._actualizar_texto, f"Error durante el listado: {e}\n")
        finally:
            self.after(0, self._finalizar_proceso)
    
    def verificar_permisos(self):
        """Verificar permisos del sistema"""
        if self.proceso_activo:
            return
        
        self.proceso_activo = True
        self._deshabilitar_botones()
        self.text_resultados.delete(1.0, tk.END)
        
        # Ejecutar en thread separado
        thread = threading.Thread(target=self._verificar_permisos_async)
        thread.daemon = True
        thread.start()
    
    def _verificar_permisos_async(self):
        """Verificación asíncrona de permisos"""
        try:
            self.after(0, self._actualizar_texto, "Verificando permisos del sistema...\n\n")
            
            # Verificar permisos sudo
            try:
                result = subprocess.run(['sudo', '-n', 'true'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.after(0, self._actualizar_texto, "✓ Permisos sudo: Disponibles\n")
                else:
                    self.after(0, self._actualizar_texto, "✗ Permisos sudo: No disponibles\n")
            except Exception as e:
                self.after(0, self._actualizar_texto, f"✗ Permisos sudo: Error - {e}\n")
            
            # Verificar permisos de archivos importantes
            archivos_importantes = [
                '/etc/passwd', '/etc/shadow', '/etc/hosts',
                '/var/log', '/tmp', '/home'
            ]
            
            for archivo in archivos_importantes:
                try:
                    result = subprocess.run(['ls', '-la', archivo], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        self.after(0, self._actualizar_texto, f"Permisos {archivo}:\n{result.stdout}\n")
                    else:
                        self.after(0, self._actualizar_texto, f"Error verificando {archivo}: {result.stderr}\n")
                except Exception as e:
                    self.after(0, self._actualizar_texto, f"Error verificando {archivo}: {e}\n")
            
            # Verificar grupos del usuario
            try:
                result = subprocess.run(['groups'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.after(0, self._actualizar_texto, f"\nGrupos del usuario:\n{result.stdout}\n")
            except Exception as e:
                self.after(0, self._actualizar_texto, f"Error obteniendo grupos: {e}\n")
                
        except Exception as e:
            self.after(0, self._actualizar_texto, f"Error durante la verificación: {e}\n")
        finally:
            self.after(0, self._finalizar_proceso)
    
    def actualizar_sistema(self):
        """Actualizar paquetes del sistema"""
        respuesta = messagebox.askyesno(
            "Actualizar Sistema",
            "¿Desea actualizar los paquetes del sistema?\n\n" +
            "Esto ejecutará: sudo apt update && sudo apt upgrade\n\n" +
            "Nota: Requiere permisos de administrador."
        )
        
        if not respuesta:
            return
        
        if self.proceso_activo:
            return
        
        self.proceso_activo = True
        self._deshabilitar_botones()
        self.text_resultados.delete(1.0, tk.END)
        
        # Ejecutar en thread separado
        thread = threading.Thread(target=self._actualizar_sistema_async)
        thread.daemon = True
        thread.start()
    
    def _actualizar_sistema_async(self):
        """Actualización asíncrona del sistema"""
        try:
            self.after(0, self._actualizar_texto, "Actualizando sistema...\n\n")
            
            # Actualizar lista de paquetes
            self.after(0, self._actualizar_texto, "Actualizando lista de paquetes...\n")
            result = subprocess.run(['sudo', 'apt', 'update'], 
                                  capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                self.after(0, self._actualizar_texto, "✓ Lista de paquetes actualizada\n\n")
            else:
                self.after(0, self._actualizar_texto, f"✗ Error actualizando lista: {result.stderr}\n\n")
                return
            
            # Actualizar paquetes
            self.after(0, self._actualizar_texto, "Actualizando paquetes instalados...\n")
            result = subprocess.run(['sudo', 'apt', 'upgrade', '-y'], 
                                  capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                self.after(0, self._actualizar_texto, "✓ Paquetes actualizados exitosamente\n")
                self.after(0, self._actualizar_texto, f"Salida:\n{result.stdout}\n")
            else:
                self.after(0, self._actualizar_texto, f"✗ Error actualizando paquetes: {result.stderr}\n")
                
        except subprocess.TimeoutExpired:
            self.after(0, self._actualizar_texto, "✗ Timeout durante la actualización\n")
        except Exception as e:
            self.after(0, self._actualizar_texto, f"Error durante la actualización: {e}\n")
        finally:
            self.after(0, self._finalizar_proceso)
    
    def _actualizar_texto(self, texto):
        """Actualizar texto en el área de resultados"""
        self.text_resultados.insert(tk.END, texto)
        self.text_resultados.see(tk.END)
        self.text_resultados.update()
    
    def _deshabilitar_botones(self):
        """Deshabilitar todos los botones durante el proceso"""
        self.btn_verificar_sistema.config(state='disabled')
        self.btn_listar_herramientas.config(state='disabled')
        self.btn_verificar_permisos.config(state='disabled')
        self.btn_actualizar.config(state='disabled')
    
    def _habilitar_botones(self):
        """Habilitar todos los botones"""
        self.btn_verificar_sistema.config(state='normal')
        self.btn_listar_herramientas.config(state='normal')
        self.btn_verificar_permisos.config(state='normal')
        self.btn_actualizar.config(state='normal')
    
    def _finalizar_proceso(self):
        """Finalizar el proceso actual"""
        self.proceso_activo = False
        self._habilitar_botones()
    
    def actualizar_vista(self):
        """Actualiza la vista con información del controlador"""
        if self.controlador:
            try:
                # Obtener información del controlador si está disponible
                if hasattr(self.controlador, 'obtener_estado_herramientas'):
                    estado = self.controlador.obtener_estado_herramientas()
                    self.logger.info(f"Estado de herramientas: {estado}")
            except Exception as e:
                self.logger.error(f"Error actualizando vista: {e}")
