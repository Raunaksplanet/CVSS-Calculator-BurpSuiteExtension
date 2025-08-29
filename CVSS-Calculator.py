from burp import IBurpExtender, ITab
from javax.swing import (JPanel, JLabel, JTextField, JButton, JTextArea, 
                         JScrollPane, BorderFactory, JComboBox, JSeparator)
from java.awt import (BorderLayout, GridBagLayout, GridBagConstraints, 
                      Insets, Font, Color, Dimension)
from java.awt.event import ActionListener
import math

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._callbacks.setExtensionName("CVSS Calculator")
        
        # Main panel
        self.main_panel = JPanel(BorderLayout())
        self.create_ui()
        
        # Register as tab
        self._callbacks.addSuiteTab(self)
    
    def create_ui(self):
        # Main container
        container = JPanel(BorderLayout())
        
        # Header
        header = self.create_header()
        container.add(header, BorderLayout.NORTH)
        
        # Content
        content = self.create_content()
        container.add(content, BorderLayout.CENTER)
        
        # Footer
        footer = self.create_footer()
        container.add(footer, BorderLayout.SOUTH)
        
        self.main_panel.add(container, BorderLayout.CENTER)
    
    def create_header(self):
        """Create clean header section"""
        header_panel = JPanel(BorderLayout())
        header_panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 10, 20))
        
        # Title
        title = JLabel("CVSS v3.1 Base Score Calculator")
        title_font = Font("SansSerif", Font.BOLD, 18)
        title.setFont(title_font)
        title.setForeground(Color(50, 50, 50))
        
        # Subtitle
        subtitle = JLabel("Calculate Common Vulnerability Scoring System scores")
        subtitle_font = Font("SansSerif", Font.PLAIN, 12)
        subtitle.setFont(subtitle_font)
        subtitle.setForeground(Color(100, 100, 100))
        
        header_content = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.anchor = GridBagConstraints.WEST
        header_content.add(title, gbc)
        
        gbc.gridy = 1
        gbc.insets = Insets(5, 0, 0, 0)
        header_content.add(subtitle, gbc)
        
        header_panel.add(header_content, BorderLayout.WEST)
        header_panel.add(JSeparator(), BorderLayout.SOUTH)
        
        return header_panel
    
    def create_content(self):
        """Create main content area"""
        content_panel = JPanel(BorderLayout())
        content_panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20))
        
        # Input section
        input_panel = self.create_input_section()
        content_panel.add(input_panel, BorderLayout.NORTH)
        
        # Results section
        results_panel = self.create_results_section()
        content_panel.add(results_panel, BorderLayout.CENTER)
        
        return content_panel
    
    def create_input_section(self):
        """Create input fields section"""
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(8, 10, 8, 10)
        gbc.anchor = GridBagConstraints.WEST
        
        # Font for labels
        label_font = Font("SansSerif", Font.PLAIN, 12)
        
        # Attack Vector
        gbc.gridx = 0; gbc.gridy = 0
        av_label = JLabel("Attack Vector:")
        av_label.setFont(label_font)
        panel.add(av_label, gbc)
        
        gbc.gridx = 1
        self.av_combo = JComboBox(["Network", "Adjacent", "Local", "Physical"])
        self.av_combo.setPreferredSize(Dimension(150, 25))
        panel.add(self.av_combo, gbc)
        
        # Attack Complexity
        gbc.gridx = 0; gbc.gridy = 1
        ac_label = JLabel("Attack Complexity:")
        ac_label.setFont(label_font)
        panel.add(ac_label, gbc)
        
        gbc.gridx = 1
        self.ac_combo = JComboBox(["Low", "High"])
        panel.add(self.ac_combo, gbc)
        
        # Privileges Required
        gbc.gridx = 0; gbc.gridy = 2
        pr_label = JLabel("Privileges Required:")
        pr_label.setFont(label_font)
        panel.add(pr_label, gbc)
        
        gbc.gridx = 1
        self.pr_combo = JComboBox(["None", "Low", "High"])
        panel.add(self.pr_combo, gbc)
        
        # User Interaction
        gbc.gridx = 0; gbc.gridy = 3
        ui_label = JLabel("User Interaction:")
        ui_label.setFont(label_font)
        panel.add(ui_label, gbc)
        
        gbc.gridx = 1
        self.ui_combo = JComboBox(["None", "Required"])
        panel.add(self.ui_combo, gbc)
        
        # Scope
        gbc.gridx = 2; gbc.gridy = 0
        gbc.insets = Insets(8, 30, 8, 10)
        s_label = JLabel("Scope:")
        s_label.setFont(label_font)
        panel.add(s_label, gbc)
        
        gbc.gridx = 3
        self.s_combo = JComboBox(["Unchanged", "Changed"])
        panel.add(self.s_combo, gbc)
        
        # Confidentiality
        gbc.gridx = 2; gbc.gridy = 1
        c_label = JLabel("Confidentiality:")
        c_label.setFont(label_font)
        panel.add(c_label, gbc)
        
        gbc.gridx = 3
        self.c_combo = JComboBox(["None", "Low", "High"])
        panel.add(self.c_combo, gbc)
        
        # Integrity
        gbc.gridx = 2; gbc.gridy = 2
        i_label = JLabel("Integrity:")
        i_label.setFont(label_font)
        panel.add(i_label, gbc)
        
        gbc.gridx = 3
        self.i_combo = JComboBox(["None", "Low", "High"])
        panel.add(self.i_combo, gbc)
        
        # Availability
        gbc.gridx = 2; gbc.gridy = 3
        a_label = JLabel("Availability:")
        a_label.setFont(label_font)
        panel.add(a_label, gbc)
        
        gbc.gridx = 3
        self.a_combo = JComboBox(["None", "Low", "High"])
        panel.add(self.a_combo, gbc)
        
        # Calculate button
        gbc.gridx = 1; gbc.gridy = 4
        gbc.gridwidth = 2
        gbc.insets = Insets(20, 10, 10, 10)
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        self.calc_button = JButton("Calculate CVSS Score")
        self.calc_button.addActionListener(CalculateListener(self))
        self.calc_button.setPreferredSize(Dimension(200, 35))
        panel.add(self.calc_button, gbc)
        
        return panel
    
    def create_results_section(self):
        """Create results display section"""
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder("Results"))
        
        self.result_area = JTextArea(8, 50)
        self.result_area.setEditable(False)
        self.result_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        
        # **FIXED: Better background color that matches dark theme**
        self.result_area.setBackground(Color(60, 63, 65))  # Dark gray like Burp's theme
        self.result_area.setForeground(Color(187, 187, 187))  # Light text for contrast
        
        self.result_area.setText("Enter CVSS metrics above and click 'Calculate CVSS Score' to see results.")
        
        scroll = JScrollPane(self.result_area)
        
        # **ALSO FIX: Match scroll pane background**
        scroll.getViewport().setBackground(Color(60, 63, 65))
        scroll.setBackground(Color(60, 63, 65))
        
        panel.add(scroll, BorderLayout.CENTER)
        
        return panel
    
    def create_footer(self):
        """Create footer section"""
        footer = JPanel(BorderLayout())
        footer.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20))
        
        info_label = JLabel("CVSS v3.1 Calculator - Base Score Only")
        info_label.setFont(Font("SansSerif", Font.ITALIC, 10))
        info_label.setForeground(Color(120, 120, 120))
        
        footer.add(info_label, BorderLayout.WEST)
        
        return footer
    
    def calculate_cvss(self):
        """Calculate CVSS base score"""
        try:
            # Value mappings
            av_values = {"Network": 0.85, "Adjacent": 0.62, "Local": 0.55, "Physical": 0.2}
            ac_values = {"Low": 0.77, "High": 0.44}
            pr_unchanged = {"None": 0.85, "Low": 0.62, "High": 0.27}
            pr_changed = {"None": 0.85, "Low": 0.68, "High": 0.5}
            ui_values = {"None": 0.85, "Required": 0.62}
            cia_values = {"None": 0.0, "Low": 0.22, "High": 0.56}
            
            # Get selected values
            av = av_values[str(self.av_combo.getSelectedItem())]
            ac = ac_values[str(self.ac_combo.getSelectedItem())]
            
            # PR depends on scope
            scope = str(self.s_combo.getSelectedItem())
            if scope == "Changed":
                pr = pr_changed[str(self.pr_combo.getSelectedItem())]
            else:
                pr = pr_unchanged[str(self.pr_combo.getSelectedItem())]
            
            ui = ui_values[str(self.ui_combo.getSelectedItem())]
            c = cia_values[str(self.c_combo.getSelectedItem())]
            i = cia_values[str(self.i_combo.getSelectedItem())]
            a = cia_values[str(self.a_combo.getSelectedItem())]
            
            # Calculate Impact
            impact = 1 - ((1 - c) * (1 - i) * (1 - a))
            
            if scope == "Unchanged":
                impact_score = 6.42 * impact
            else:
                impact_score = 7.52 * (impact - 0.029) - 3.25 * pow((impact - 0.02), 15)
            
            # Calculate Exploitability
            exploitability = 8.22 * av * ac * pr * ui
            
            # Calculate Base Score
            if impact <= 0:
                base_score = 0.0
            else:
                if scope == "Unchanged":
                    base_score = min(impact_score + exploitability, 10.0)
                else:
                    base_score = min(1.08 * (impact_score + exploitability), 10.0)
            
            # Round to 1 decimal place
            base_score = round(base_score, 1)
            
            # Determine severity rating
            if base_score == 0.0:
                severity = "None"
            elif base_score <= 3.9:
                severity = "Low"
            elif base_score <= 6.9:
                severity = "Medium" 
            elif base_score <= 8.9:
                severity = "High"
            else:
                severity = "Critical"
            
            # Create vector string abbreviations
            av_abbrev = {"Network": "N", "Adjacent": "A", "Local": "L", "Physical": "P"}
            ac_abbrev = {"Low": "L", "High": "H"}
            pr_abbrev = {"None": "N", "Low": "L", "High": "H"}
            ui_abbrev = {"None": "N", "Required": "R"}
            s_abbrev = {"Unchanged": "U", "Changed": "C"}
            cia_abbrev = {"None": "N", "Low": "L", "High": "H"}
            
            # Format results
            result_text = "CVSS v3.1 Base Score Calculation Results\n"
            result_text += "=" * 45 + "\n\n"
            result_text += "Base Score: {}/10.0 ({})\n\n".format(base_score, severity)
            result_text += "Vector String: CVSS:3.1/"
            result_text += "AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}\n\n".format(
                av_abbrev[str(self.av_combo.getSelectedItem())],
                ac_abbrev[str(self.ac_combo.getSelectedItem())],
                pr_abbrev[str(self.pr_combo.getSelectedItem())],
                ui_abbrev[str(self.ui_combo.getSelectedItem())],
                s_abbrev[str(self.s_combo.getSelectedItem())],
                cia_abbrev[str(self.c_combo.getSelectedItem())],
                cia_abbrev[str(self.i_combo.getSelectedItem())],
                cia_abbrev[str(self.a_combo.getSelectedItem())]
            )
            result_text += "Metric Details:\n"
            result_text += "-" * 15 + "\n"
            result_text += "Attack Vector: {}\n".format(self.av_combo.getSelectedItem())
            result_text += "Attack Complexity: {}\n".format(self.ac_combo.getSelectedItem())
            result_text += "Privileges Required: {}\n".format(self.pr_combo.getSelectedItem())
            result_text += "User Interaction: {}\n".format(self.ui_combo.getSelectedItem())
            result_text += "Scope: {}\n".format(self.s_combo.getSelectedItem())
            result_text += "Confidentiality: {}\n".format(self.c_combo.getSelectedItem())
            result_text += "Integrity: {}\n".format(self.i_combo.getSelectedItem())
            result_text += "Availability: {}\n".format(self.a_combo.getSelectedItem())
            result_text += "\nCalculation Components:\n"
            result_text += "-" * 22 + "\n"
            result_text += "Impact Score: {:.1f}\n".format(impact_score)
            result_text += "Exploitability Score: {:.1f}\n".format(exploitability)
            
            self.result_area.setText(result_text)
            
        except Exception as e:
            self.result_area.setText("Error calculating CVSS score: {}".format(str(e)))
    
    def getTabCaption(self):
        return "CVSS Calculator"
    
    def getUiComponent(self):
        return self.main_panel

class CalculateListener(ActionListener):
    def __init__(self, calculator):
        self.calculator = calculator
    
    def actionPerformed(self, event):
        self.calculator.calculate_cvss()
