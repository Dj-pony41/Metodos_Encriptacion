   M S B A M L   `   `   `  ����E  AAeropuerto, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'clr-namespace:Aeropuerto
Aeropuerto  5   	       Aeropuerto.MainWindow   5   	   R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   *localclr-namespace:Aeropuerto     5   	     � Title$  
MainWindow��5   	   $	��450��6   $	��700��6)   ���#FEF6E4.��5
      � -   5         �Name$ MainGrid��5
      .+�5   
   �� $(��"Ingrese la clave de encriptación:��6   $
��Left=�5      $��	10,60,0,0q�5      $	��Top=�5      ���#0018586(   �� 5   
   -   5         ��Name$ 
KeyTextBox��5      $
��Left=�5      $��	10,85,0,0q�5      $	��Top=�5      $	��300��5      $��20��6   ���#f3d2c1���#001858���#001858$	��2pxq�6j   �� 5   
   -   5        $��Verificar Key��5      $
��Left=�5      $��
320,85,0,0q�5      $	��Top=�5      ���#f582ae���#001858���#001858$	��2pxq�6i   �� 5    
   $��
Empleados:��6   $
��Left=�5!      $��
10,130,0,0q�5"      $	��Top=�5#      ���#0018586(   �� 5%   
   -   5         ��Name$ EmployeesComboBox��5%      $
��Left=�5&      $��
10,155,0,0q�5'      $	��Top=�5(      $	��300��5)      ���#001858���#001858$	��2pxq�5*   u   &   System.Windows.Controls.DataGrid  5,   
   -   5          Name$ EmployeeDataGrid��5,      $
��Left=�5-      $��
10,200,0,0q�5.      $	��Top=�5/      $	��200��50      $	��650��51         AutoGenerateColumns .  ���#f3d2c1���#001858���#001858$	��2pxq�52   g      Columns 54      0  *System.Windows.Controls.DataGridTextColumn  56      ,  &System.Windows.Controls.DataGridColumn   Header$ Fecha��6%      Width5  /System.Windows.Controls.DataGridLengthConverter$ * 58      1  +System.Windows.Controls.DataGridBoundColumn	   Binding	 57      �� *Date+
 �� StringFormat$
 {0:dd/MM/yyyy}��58        5;      $ 
Entrada AM��6%   $ * 5=      	 5<      �� *	EntradaAM+   ElementStyle 5>      �� 5?       �� 
TargetType" ��6     �� Triggers 5@      �� 5B   "    �� Binding 6.   �� *IsEntradaAMOutOfRange+ �� Value True6X   .a�5C   &   ��  �� Property � �� �� Value
 �  ��6C   5D   #   5F      5H        5K      $ 	Salida AM��6%   $ * 5M      	 5L      �� *
SalidaAM+ 5N      �� 5O      " ��6     5P      �� 5R   "    6.   �� *IsSalidaAMOutOfRange+ True6W   .a�5S   &   ��  � ��
 �  ��6C   5T   #   5V      5X        5[      $ 
Entrada PM��6%   $ * 5]      	 5\      �� *	EntradaPM+ 5^      �� 5_      " ��6     5`      �� 5b   "    6.   �� *IsEntradaPMOutOfRange+ True6X   .a�5c   &   ��  � ��
 �  ��6C   5d   #   5f      5h        5k      $ 	Salida PM��6%   $ * 5m      	 5l      �� *
SalidaPM+ 5n      �� 5o      " ��6     5p      �� 5r   "    6.   �� *IsSalidaPMOutOfRange+ True6W   .a�5s   &   ��  � ��
 �  ��6C   5t   #   5v      5x      5z      �� 5|   
   -   5        $��Generar Reporte��5|      $
��Left=�5~   	   $��	10,33,0,0q�5   	   $	��Top=�5�   	   ���#8bd3dd���#001858���#001858$	��2pxq�6a   5�      5�      