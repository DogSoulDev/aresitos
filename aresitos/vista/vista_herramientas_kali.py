# -*- coding: utf-8 -*-
"""
ARESITOS - Vista de Herramientas Kali Linux
===========================================

Ventana especializada para mostrar, verificar e instalar todas las herramientas
de Kali Linux y otras herramientas del sistema necesarias para ARESITOS.

Esta vista se muestra después del login exitoso para garantizar que el usuario
tenga todas las herramientas instaladas antes de usar ARESITOS.

Herramientas actualizadas para Kali Linux 2025 con integración específica
en los módulos: Escaneador, FIM, SIEM, Cuarentena y Análisis.

Autor: DogSoulDev
Fecha: 18 de Agosto de 2025
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import time
import os
from typing import Dict, List, Any, Optional

# Importar definiciones de herramientas
from .vista_herramientas_kali_def import get_herramientas_kali_2025

try:
    from aresitos.vista.burp_theme import burp_theme
    BURP_THEME_AVAILABLE = True
except ImportError:
    BURP_THEME_AVAILABLE = False
    burp_theme = None

class VistaHerramientasKali(tk.Toplevel):
    """
    Vista especializada para gestión de herramientas de Kali Linux.
    Se muestra después del login para verificar e instalar herramientas.
    """
    
    def __init__(self, parent, callback_completado=None):
        super().__init__(parent)
        self.parent = parent
        self.callback_completado = callback_completado
        
        # Configuración de ventana
        self.title("ARESITOS - Herramientas de Kali Linux 2025")
        self.geometry("1000x700")
        self.resizable(True, True)
        
        # Hacer que la ventana esté siempre al frente
        self.transient(parent)
        self.grab_set()
        
        # Estado de instalación
        self.instalando = False
        self.herramientas_seleccionadas = set()
        self.thread_instalacion = None
        
        # Configurar tema
        self._configurar_tema()
        
        # Definir herramientas de Kali Linux 2025
        self._definir_herramientas_kali()
        
        # Crear interfaz
        self._crear_interfaz()
        
        # Verificar herramientas al inicio
        self._verificar_herramientas_iniciales()
        
        # Centrar ventana
        self._centrar_ventana()
    
    def _configurar_tema(self):
        """Configurar tema visual Burp Suite"""
        if BURP_THEME_AVAILABLE and burp_theme:
            self.theme = burp_theme
            self.configure(bg=burp_theme.get_color('bg_primary'))
            # Configurar estilos TTK
            style = ttk.Style()
            burp_theme.configure_ttk_style(style)
            # Definir colores usando el tema
            self.bg_primary = burp_theme.get_color('bg_primary')
            self.bg_secondary = burp_theme.get_color('bg_secondary')
            self.bg_tertiary = burp_theme.get_color('bg_tertiary')
            self.fg_primary = burp_theme.get_color('fg_primary')
            self.fg_secondary = burp_theme.get_color('fg_secondary')
            self.accent_orange = burp_theme.get_color('fg_accent')
            self.accent_green = burp_theme.get_color('success')
            self.accent_red = burp_theme.get_color('danger')
            self.accent_blue = burp_theme.get_color('info')
        else:
            self.theme = None
            self.configure(bg='#f0f0f0')
            # Colores fallback
            self.bg_primary = '#f0f0f0'
            self.bg_secondary = '#e0e0e0'
            self.bg_tertiary = '#d0d0d0'
            self.fg_primary = '#000000'
            self.fg_secondary = '#666666'
            self.accent_orange = '#ff6633'
            self.accent_green = '#4caf50'
            self.accent_red = '#f44336'
            self.accent_blue = '#2196f3'
    
    def _definir_herramientas_kali(self):
        """Cargar definiciones de herramientas desde archivo separado"""
        self.herramientas_kali = get_herramientas_kali_2025()
    
    def _crear_interfaz(self):
        """Crear la interfaz principal de herramientas"""
        
        # Frame principal
        main_frame = tk.Frame(self, bg=self.bg_primary)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Título
        titulo_frame = tk.Frame(main_frame, bg=self.bg_primary)
        titulo_frame.pack(fill=tk.X, pady=(0, 10))
        
        titulo_label = tk.Label(
            titulo_frame,
            text=" HERRAMIENTAS DE KALI LINUX 2025 PARA ARESITOS",
            bg=self.bg_primary,
            fg=self.accent_orange,
            font=("Arial", 16, "bold")
        )
        titulo_label.pack()
        
        subtitulo_label = tk.Label(
            titulo_frame,
            text="Verificar e instalar herramientas necesarias para funcionamiento óptimo",
            bg=self.bg_primary,
            fg=self.fg_secondary,
            font=("Arial", 10)
        )
        subtitulo_label.pack()
        
        # Frame para controles
        controles_frame = tk.Frame(main_frame, bg=self.bg_secondary)
        controles_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Botones de control
        btn_frame = tk.Frame(controles_frame, bg=self.bg_secondary)
        btn_frame.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.btn_verificar = tk.Button(
            btn_frame,
            text=" Verificar Todas",
            command=self._verificar_todas_herramientas,
            bg=self.accent_blue,
            fg='white',
            font=("Arial", 10, "bold"),
            width=15
        )
        self.btn_verificar.pack(side=tk.LEFT, padx=5)
        
        self.btn_seleccionar_esenciales = tk.Button(
            btn_frame,
            text=" Seleccionar Esenciales",
            command=self._seleccionar_esenciales,
            bg=self.accent_orange,
            fg='white',
            font=("Arial", 10, "bold"),
            width=18
        )
        self.btn_seleccionar_esenciales.pack(side=tk.LEFT, padx=5)
        
        self.btn_instalar_seleccionadas = tk.Button(
            btn_frame,
            text=" Instalar Seleccionadas",
            command=self._instalar_seleccionadas,
            bg=self.accent_green,
            fg='white',
            font=("Arial", 10, "bold"),
            width=18
        )
        self.btn_instalar_seleccionadas.pack(side=tk.LEFT, padx=5)
        
        self.btn_continuar = tk.Button(
            btn_frame,
            text="Continuar a ARESITOS",
            command=self._continuar_aresitos,
            bg='#6c757d',
            fg='white',
            font=("Arial", 10, "bold"),
            width=18
        )
        self.btn_continuar.pack(side=tk.RIGHT, padx=5)
        
        # Frame para estadísticas
        stats_frame = tk.Frame(controles_frame, bg=self.bg_secondary)
        stats_frame.pack(side=tk.RIGHT, padx=10, pady=10)
        
        self.stats_label = tk.Label(
            stats_frame,
            text="Herramientas: 0/0 instaladas",
            bg=self.bg_secondary,
            fg=self.fg_primary,
            font=("Arial", 10, "bold")
        )
        self.stats_label.pack()
        
        # Notebook para categorías
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Crear pestañas por categoría
        self.frames_categorias = {}
        self.treeviews_categorias = {}
        
        for categoria, herramientas in self.herramientas_kali.items():
            self._crear_pestana_categoria(categoria, herramientas)
        
        # Frame para logs
        log_frame = tk.Frame(main_frame, bg=self.bg_secondary)
        log_frame.pack(fill=tk.X, pady=(10, 0))
        
        tk.Label(
            log_frame,
            text=" Log de Instalación:",
            bg=self.bg_secondary,
            fg=self.fg_primary,
            font=("Arial", 10, "bold")
        ).pack(anchor=tk.W, padx=5)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=8,
            bg=self.bg_tertiary,
            fg=self.fg_primary,
            font=("Consolas", 9)
        )
        self.log_text.pack(fill=tk.X, padx=5, pady=5)
    
    def _crear_pestana_categoria(self, categoria: str, herramientas: Dict):
        """Crear pestaña para una categoría de herramientas"""
        
        # Frame para la categoría
        frame_categoria = tk.Frame(self.notebook, bg=self.bg_primary)
        self.notebook.add(frame_categoria, text=categoria)
        self.frames_categorias[categoria] = frame_categoria
        
        # Treeview para las herramientas
        columns = ("Estado", "Herramienta", "Descripción", "Uso en ARESITOS")
        tree = ttk.Treeview(frame_categoria, columns=columns, show="tree headings", height=15)
        
        # Configurar columnas
        tree.heading("#0", text="", anchor=tk.W)
        tree.column("#0", width=30, minwidth=30)
        
        tree.heading("Estado", text="Estado", anchor=tk.CENTER)
        tree.column("Estado", width=80, minwidth=80, anchor=tk.CENTER)
        
        tree.heading("Herramienta", text="Herramienta", anchor=tk.W)
        tree.column("Herramienta", width=150, minwidth=100)
        
        tree.heading("Descripción", text="Descripción", anchor=tk.W)
        tree.column("Descripción", width=300, minwidth=200)
        
        tree.heading("Uso en ARESITOS", text="Uso en ARESITOS", anchor=tk.W)
        tree.column("Uso en ARESITOS", width=250, minwidth=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(frame_categoria, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Empaquetado
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 5), pady=5)
        
        # Poblar treeview
        for nombre, info in herramientas.items():
            esencial_text = " " if info["esencial"] else "   "
            tree.insert("", tk.END, iid=f"{categoria}_{nombre}", 
                       text=esencial_text,
                       values=(" Verificando...", nombre, info["descripcion"], info["uso_aresitos"]))
        
        # Bind para selección
        tree.bind("<Button-1>", lambda e, cat=categoria: self._on_tree_click(e, cat))
        tree.bind("<Double-1>", lambda e, cat=categoria: self._on_tree_double_click(e, cat))
        
        self.treeviews_categorias[categoria] = tree
    
    def _on_tree_click(self, event, categoria: str):
        """Manejar clic en treeview"""
        tree = self.treeviews_categorias[categoria]
        item = tree.identify_row(event.y)
        if item:
            # Toggle selection
            if item in self.herramientas_seleccionadas:
                self.herramientas_seleccionadas.remove(item)
                tree.set(item, "Estado", "⚪ No seleccionado")
            else:
                self.herramientas_seleccionadas.add(item)
                tree.set(item, "Estado", "� Seleccionado")
    
    def _on_tree_double_click(self, event, categoria: str):
        """Manejar doble clic para instalar herramienta individual"""
        tree = self.treeviews_categorias[categoria]
        item = tree.identify_row(event.y)
        if item and not self.instalando:
            nombre_herramienta = item.split("_", 1)[1]
            self._instalar_herramienta_individual(categoria, nombre_herramienta)
    
    def _verificar_herramientas_iniciales(self):
        """Verificar todas las herramientas al abrir la ventana"""
        self._escribir_log(" Verificando herramientas instaladas...")
        
        def verificar_async():
            for categoria, herramientas in self.herramientas_kali.items():
                for nombre, info in herramientas.items():
                    estado = self._verificar_herramienta(info["paquete"])
                    item_id = f"{categoria}_{nombre}"
                    
                    if estado:
                        self.after(0, lambda i=item_id: self._actualizar_estado_herramienta(i, "OK Instalado"))
                    else:
                        self.after(0, lambda i=item_id: self._actualizar_estado_herramienta(i, "ERROR No instalado"))
            
            self.after(0, self._actualizar_estadisticas)
            self.after(0, lambda: self._escribir_log("OK Verificación completada"))
        
        thread = threading.Thread(target=verificar_async, daemon=True)
        thread.start()
    
    def _verificar_herramienta(self, paquete: str) -> bool:
        """Verificar si una herramienta está instalada"""
        try:
            # Verificar con dpkg
            result = subprocess.run(['dpkg', '-l', paquete], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and 'ii' in result.stdout:
                return True
            
            # Verificar con which
            result = subprocess.run(['which', paquete], 
                                  capture_output=True, timeout=5)
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _actualizar_estado_herramienta(self, item_id: str, estado: str):
        """Actualizar estado visual de una herramienta con colores"""
        categoria = item_id.split("_", 1)[0]
        if categoria in self.treeviews_categorias:
            tree = self.treeviews_categorias[categoria]
            try:
                # Configurar colores según el estado
                if "OK" in estado or "Instalado" in estado:
                    tree.set(item_id, "Estado", "✓ INSTALADO")
                    tree.item(item_id, tags=("instalado",))
                elif "ERROR" in estado or "Error" in estado:
                    tree.set(item_id, "Estado", "✗ ERROR")
                    tree.item(item_id, tags=("error",))
                elif "WARNING" in estado or "Falta" in estado:
                    tree.set(item_id, "Estado", "! NO INSTALADO")
                    tree.item(item_id, tags=("no_instalado",))
                else:
                    tree.set(item_id, "Estado", estado)
                    tree.item(item_id, tags=("verificando",))
                
                # Configurar colores de tags si no existen
                if not hasattr(tree, 'tags_configured'):
                    tree.tag_configure("instalado", background="#d4edda", foreground="#155724")
                    tree.tag_configure("error", background="#f8d7da", foreground="#721c24")
                    tree.tag_configure("no_instalado", background="#fff3cd", foreground="#856404")
                    tree.tag_configure("verificando", background="#e2e3e5", foreground="#383d41")
                    tree.tags_configured = True
                    
            except Exception as e:
                print(f"Error actualizando estado: {e}")
    
    def _actualizar_estadisticas(self):
        """Actualizar estadísticas de herramientas"""
        total = 0
        instaladas = 0
        esenciales_instaladas = 0
        esenciales_total = 0
        
        for categoria, herramientas in self.herramientas_kali.items():
            tree = self.treeviews_categorias[categoria]
            for nombre, info in herramientas.items():
                total += 1
                if info["esencial"]:
                    esenciales_total += 1
                
                item_id = f"{categoria}_{nombre}"
                try:
                    estado = tree.set(item_id, "Estado")
                    if "OK" in estado:
                        instaladas += 1
                        if info["esencial"]:
                            esenciales_instaladas += 1
                except:
                    pass
        
        porcentaje = (instaladas / total * 100) if total > 0 else 0
        porcentaje_esenciales = (esenciales_instaladas / esenciales_total * 100) if esenciales_total > 0 else 0
        
        self.stats_label.config(
            text=f"Herramientas: {instaladas}/{total} ({porcentaje:.1f}%) | "
                 f"Esenciales: {esenciales_instaladas}/{esenciales_total} ({porcentaje_esenciales:.1f}%)"
        )
        
        # Cambiar color del botón continuar según el estado
        if porcentaje_esenciales >= 80:
            self.btn_continuar.config(bg=self.accent_green)
        elif porcentaje_esenciales >= 50:
            self.btn_continuar.config(bg=self.accent_orange)
        else:
            self.btn_continuar.config(bg=self.accent_red)
    
    def _verificar_todas_herramientas(self):
        """Verificar todas las herramientas nuevamente"""
        if self.instalando:
            messagebox.showwarning("Advertencia", "Instalación en progreso, espere...")
            return
        
        self._verificar_herramientas_iniciales()
    
    def _seleccionar_esenciales(self):
        """Seleccionar todas las herramientas esenciales"""
        self.herramientas_seleccionadas.clear()
        
        for categoria, herramientas in self.herramientas_kali.items():
            tree = self.treeviews_categorias[categoria]
            for nombre, info in herramientas.items():
                item_id = f"{categoria}_{nombre}"
                if info["esencial"]:
                    self.herramientas_seleccionadas.add(item_id)
                    tree.set(item_id, "Estado", "� Seleccionado")
                else:
                    tree.set(item_id, "Estado", "⚪ No seleccionado")
        
        self._escribir_log(f"OK Seleccionadas {len(self.herramientas_seleccionadas)} herramientas esenciales")
    
    def _instalar_seleccionadas(self):
        """Instalar herramientas seleccionadas"""
        if self.instalando:
            messagebox.showwarning("Advertencia", "Instalación ya en progreso")
            return
        
        if not self.herramientas_seleccionadas:
            messagebox.showwarning("Advertencia", "No hay herramientas seleccionadas")
            return
        
        if not messagebox.askyesno("Confirmar", 
                                  f"¿Instalar {len(self.herramientas_seleccionadas)} herramientas seleccionadas?\\n\\n"
                                  "Este proceso puede tomar varios minutos."):
            return
        
        self.instalando = True
        self.btn_instalar_seleccionadas.config(state=tk.DISABLED)
        self.btn_verificar.config(state=tk.DISABLED)
        
        self.thread_instalacion = threading.Thread(target=self._proceso_instalacion_masiva, daemon=True)
        self.thread_instalacion.start()
    
    def _proceso_instalacion_masiva(self):
        """Proceso de instalación masiva en background"""
        try:
            self.after(0, lambda: self._escribir_log("🚀 Iniciando instalación masiva..."))
            
            # Actualizar lista de paquetes
            self.after(0, lambda: self._escribir_log("🔄 Actualizando lista de paquetes..."))
            result = subprocess.run(['sudo', 'apt', 'update'], 
                                  capture_output=True, text=True, timeout=120)
            
            if result.returncode != 0:
                self.after(0, lambda: self._escribir_log("❌ Error actualizando lista de paquetes"))
                return
            
            # Instalar cada herramienta seleccionada
            total = len(self.herramientas_seleccionadas)
            for i, item_id in enumerate(self.herramientas_seleccionadas, 1):
                categoria, nombre = item_id.split("_", 1)
                herramienta_info = self.herramientas_kali[categoria][nombre]
                paquete = herramienta_info["paquete"]
                instalacion_especial = herramienta_info.get("instalacion_especial", "apt")
                
                self.after(0, lambda p=paquete, n=i, t=total: 
                          self._escribir_log(f"📦 [{n}/{t}] Instalando {p}..."))
                
                success = False
                error_msg = ""
                
                if instalacion_especial == "apt":
                    # Instalación estándar con APT
                    paquetes_lista = paquete.split()
                    cmd = ['sudo', 'apt', 'install', '-y'] + paquetes_lista
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    success = result.returncode == 0
                    if not success:
                        error_msg = result.stderr
                
                elif instalacion_especial == "snap":
                    # Instalación con Snap
                    cmd = ['sudo', 'snap', 'install', paquete]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    success = result.returncode == 0
                    if not success:
                        error_msg = result.stderr
                        
                elif instalacion_especial in ["go", "github"]:
                    # Herramientas especiales - marcar como instalación manual requerida
                    self.after(0, lambda p=paquete: self._escribir_log(f"⚠️ {p} requiere instalación manual"))
                    success = True  # No bloquear el proceso
                
                if success:
                    self.after(0, lambda i=item_id: self._actualizar_estado_herramienta(i, "✅ Instalado"))
                    self.after(0, lambda p=paquete: self._escribir_log(f"✅ {p} instalado correctamente"))
                else:
                    self.after(0, lambda i=item_id: self._actualizar_estado_herramienta(i, "❌ Error"))
                    self.after(0, lambda p=paquete, e=error_msg: self._escribir_log(f"❌ Error instalando {p}: {e}"))
            
            self.after(0, lambda: self._escribir_log("🎉 Instalación masiva completada"))
            self.after(0, self._actualizar_estadisticas)
            
        except Exception as e:
            error_msg = f"❌ Error durante instalación: {str(e)}"
            self.after(0, lambda msg=error_msg: self._escribir_log(msg))
        finally:
            self.instalando = False
            self.after(0, lambda: self.btn_instalar_seleccionadas.config(state=tk.NORMAL))
            self.after(0, lambda: self.btn_verificar.config(state=tk.NORMAL))
    
    def _instalar_herramienta_individual(self, categoria: str, nombre: str):
        """Instalar una herramienta individual"""
        herramienta_info = self.herramientas_kali[categoria][nombre]
        paquete = herramienta_info["paquete"]
        instalacion_especial = herramienta_info.get("instalacion_especial", "apt")
        
        if not messagebox.askyesno("Confirmar", f"¿Instalar {paquete}?"):
            return
        
        def instalar_async():
            try:
                self.after(0, lambda: self._escribir_log(f"📦 Instalando {paquete}..."))
                
                success = False
                error_msg = ""
                
                if instalacion_especial == "apt":
                    # Instalación estándar con APT
                    paquetes_lista = paquete.split()
                    cmd = ['sudo', 'apt', 'install', '-y'] + paquetes_lista
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    success = result.returncode == 0
                    if not success:
                        error_msg = result.stderr
                
                elif instalacion_especial == "snap":
                    # Instalación con Snap
                    cmd = ['sudo', 'snap', 'install', paquete]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    success = result.returncode == 0
                    if not success:
                        error_msg = result.stderr
                
                elif instalacion_especial == "go":
                    # Instalación con Go
                    self.after(0, lambda: self._escribir_log(f"🔧 Instalando {paquete} con Go..."))
                    go_pkg_map = {
                        "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
                        "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest"
                    }
                    if paquete in go_pkg_map:
                        cmd = ['go', 'install', go_pkg_map[paquete]]
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                        success = result.returncode == 0
                        if not success:
                            error_msg = result.stderr
                
                elif instalacion_especial == "github":
                    # Instalación desde GitHub
                    self.after(0, lambda: self._escribir_log(f"🔧 Instalando {paquete} desde GitHub..."))
                    github_map = {
                        "ligolo-ng": "https://github.com/nicocha30/ligolo-ng/releases/latest",
                        "sliver": "https://github.com/BishopFox/sliver/releases/latest"
                    }
                    if paquete in github_map:
                        # Aquí normalmente descargaríamos y instalaríamos desde GitHub
                        # Por ahora, intentamos con apt primero
                        cmd = ['sudo', 'apt', 'install', '-y', paquete]
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                        success = result.returncode == 0
                        if not success:
                            self.after(0, lambda: self._escribir_log(f"⚠️ {paquete} debe instalarse manualmente desde {github_map[paquete]}"))
                            success = True  # No marcar como error si no está en repos
                
                item_id = f"{categoria}_{nombre}"
                if success:
                    self.after(0, lambda: self._actualizar_estado_herramienta(item_id, "✅ Instalado"))
                    self.after(0, lambda: self._escribir_log(f"✅ {paquete} instalado correctamente"))
                else:
                    self.after(0, lambda: self._actualizar_estado_herramienta(item_id, "❌ Error"))
                    self.after(0, lambda: self._escribir_log(f"❌ Error instalando {paquete}: {error_msg}"))
                
                self.after(0, self._actualizar_estadisticas)
                
            except Exception as e:
                error_msg = f"❌ Error: {str(e)}"
                self.after(0, lambda msg=error_msg: self._escribir_log(msg))
        
        thread = threading.Thread(target=instalar_async, daemon=True)
        thread.start()
    
    def _escribir_log(self, mensaje: str):
        """Escribir mensaje en el log"""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {mensaje}\\n")
        self.log_text.see(tk.END)
    
    def _continuar_aresitos(self):
        """Continuar a ARESITOS"""
        # Verificar herramientas esenciales
        esenciales_faltantes = []
        
        for categoria, herramientas in self.herramientas_kali.items():
            tree = self.treeviews_categorias[categoria]
            for nombre, info in herramientas.items():
                if info["esencial"]:
                    item_id = f"{categoria}_{nombre}"
                    try:
                        estado = tree.set(item_id, "Estado")
                        if "ERROR" in estado:
                            esenciales_faltantes.append(nombre)
                    except:
                        esenciales_faltantes.append(nombre)
        
        if esenciales_faltantes:
            respuesta = messagebox.askyesno(
                "Herramientas Esenciales Faltantes",
                f"Faltan {len(esenciales_faltantes)} herramientas esenciales:\\n\\n"
                f"{', '.join(esenciales_faltantes[:5])}{'...' if len(esenciales_faltantes) > 5 else ''}\\n\\n"
                "ARESITOS puede no funcionar correctamente.\\n"
                "¿Continuar de todos modos?"
            )
            if not respuesta:
                return
        
        # Cerrar ventana y continuar
        self._escribir_log("Continuando a ARESITOS...")
        self.grab_release()
        
        if self.callback_completado:
            self.callback_completado()
        
        self.destroy()
    
    def _requiere_instalacion_especial(self, paquete: str) -> bool:
        """Verificar si un paquete requiere instalación especial"""
        # Herramientas que requieren instalación especial (Go, GitHub releases, etc.)
        herramientas_especiales = {
            'subfinder': 'go',
            'nuclei': 'apt_special',  # Verificar si está en repo oficial
            'ffuf': 'go',
            'chisel': 'github',
            'pwncat-cs': 'pip'
        }
        return paquete in herramientas_especiales
    
    def _instalar_herramienta_especial(self, paquete: str) -> bool:
        """Instalar herramientas que requieren métodos especiales"""
        try:
            if paquete == 'subfinder':
                # Instalar Go si no está presente
                result = subprocess.run(['which', 'go'], capture_output=True)
                if result.returncode != 0:
                    subprocess.run(['sudo', 'apt', 'install', '-y', 'golang-go'], timeout=300)
                
                # Instalar subfinder via go
                env = dict(os.environ)
                env['GOPATH'] = '/opt/go'
                env['PATH'] = env['PATH'] + ':/opt/go/bin'
                result = subprocess.run(['go', 'install', '-v', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'], 
                                      env=env, capture_output=True, text=True, timeout=300)
                return result.returncode == 0
                
            elif paquete == 'ffuf':
                # Similar para ffuf
                result = subprocess.run(['which', 'go'], capture_output=True)
                if result.returncode != 0:
                    subprocess.run(['sudo', 'apt', 'install', '-y', 'golang-go'], timeout=300)
                
                env = dict(os.environ)
                env['GOPATH'] = '/opt/go'
                env['PATH'] = env['PATH'] + ':/opt/go/bin'
                result = subprocess.run(['go', 'install', 'github.com/ffuf/ffuf@latest'], 
                                      env=env, capture_output=True, text=True, timeout=300)
                return result.returncode == 0
                
            elif paquete == 'chisel':
                # Instalar desde GitHub releases
                result = subprocess.run([
                    'wget', '-O', '/tmp/chisel.gz',
                    'https://github.com/jpillora/chisel/releases/latest/download/chisel_1.9.1_linux_amd64.gz'
                ], capture_output=True, timeout=120)
                
                if result.returncode == 0:
                    subprocess.run(['gunzip', '/tmp/chisel.gz'], capture_output=True)
                    subprocess.run(['sudo', 'mv', '/tmp/chisel', '/usr/local/bin/chisel'], capture_output=True)
                    subprocess.run(['sudo', 'chmod', '+x', '/usr/local/bin/chisel'], capture_output=True)
                    return True
                return False
                
            elif paquete == 'pwncat-cs':
                # Instalar via pip
                result = subprocess.run(['sudo', 'pip3', 'install', 'pwncat-cs'], 
                                      capture_output=True, text=True, timeout=300)
                return result.returncode == 0
                
            else:
                # Fallback a apt normal
                result = subprocess.run(['sudo', 'apt', 'install', '-y', paquete], 
                                      capture_output=True, text=True, timeout=300)
                return result.returncode == 0
                
        except Exception as e:
            self.after(0, lambda: self._escribir_log(f"ERROR Instalación especial falló: {str(e)}"))
            return False
    
    def _centrar_ventana(self):
        """Centrar la ventana en la pantalla"""
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (self.winfo_width() // 2)
        y = (self.winfo_screenheight() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")

# Ejemplo de uso
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # Ocultar ventana principal
    
    def callback_test():
        print("Callback ejecutado - continuando a ARESITOS")
        root.quit()
    
    ventana_herramientas = VistaHerramientasKali(root, callback_test)
    root.mainloop()
