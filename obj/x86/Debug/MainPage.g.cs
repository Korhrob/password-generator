﻿#pragma checksum "F:\Passgen\Passgen\MainPage.xaml" "{8829d00f-11b8-4213-878b-770e8597ac16}" "68FB865699D28960276E380EF7886E3CAF61CAF503E4834609574EE1ADD263E8"
//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Passgen
{
    partial class MainPage : 
        global::Windows.UI.Xaml.Controls.Page, 
        global::Windows.UI.Xaml.Markup.IComponentConnector,
        global::Windows.UI.Xaml.Markup.IComponentConnector2
    {
        /// <summary>
        /// Connect()
        /// </summary>
        [global::System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Windows.UI.Xaml.Build.Tasks"," 10.0.19041.685")]
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
        public void Connect(int connectionId, object target)
        {
            switch(connectionId)
            {
            case 2: // MainPage.xaml line 52
                {
                    this.target = (global::Windows.UI.Xaml.Controls.Button)(target);
                    ((global::Windows.UI.Xaml.Controls.Button)this.target).Click += this.fetch_Click;
                }
                break;
            case 3: // MainPage.xaml line 53
                {
                    this.targetResult = (global::Windows.UI.Xaml.Controls.ComboBox)(target);
                }
                break;
            case 4: // MainPage.xaml line 56
                {
                    this.load = (global::Windows.UI.Xaml.Controls.Button)(target);
                    ((global::Windows.UI.Xaml.Controls.Button)this.load).Click += this.copy_Click;
                }
                break;
            case 5: // MainPage.xaml line 57
                {
                    this.remove = (global::Windows.UI.Xaml.Controls.Button)(target);
                    ((global::Windows.UI.Xaml.Controls.Button)this.remove).Click += this.remove_Click;
                }
                break;
            case 6: // MainPage.xaml line 46
                {
                    this.generate = (global::Windows.UI.Xaml.Controls.Button)(target);
                    ((global::Windows.UI.Xaml.Controls.Button)this.generate).Click += this.generate_Click;
                }
                break;
            case 7: // MainPage.xaml line 47
                {
                    this.result = (global::Windows.UI.Xaml.Controls.TextBox)(target);
                }
                break;
            case 8: // MainPage.xaml line 49
                {
                    this.save = (global::Windows.UI.Xaml.Controls.Button)(target);
                    ((global::Windows.UI.Xaml.Controls.Button)this.save).Click += this.save_Click;
                }
                break;
            case 9: // MainPage.xaml line 29
                {
                    this.settings = (global::Windows.UI.Xaml.Controls.StackPanel)(target);
                }
                break;
            case 10: // MainPage.xaml line 37
                {
                    this.uppercase = (global::Windows.UI.Xaml.Controls.CheckBox)(target);
                }
                break;
            case 11: // MainPage.xaml line 38
                {
                    this.lowercase = (global::Windows.UI.Xaml.Controls.CheckBox)(target);
                }
                break;
            case 12: // MainPage.xaml line 39
                {
                    this.digit = (global::Windows.UI.Xaml.Controls.CheckBox)(target);
                }
                break;
            case 13: // MainPage.xaml line 40
                {
                    this.symbol = (global::Windows.UI.Xaml.Controls.CheckBox)(target);
                }
                break;
            case 14: // MainPage.xaml line 32
                {
                    this.length = (global::Windows.UI.Xaml.Controls.TextBox)(target);
                    ((global::Windows.UI.Xaml.Controls.TextBox)this.length).TextChanged += this.length_TextChanged;
                }
                break;
            default:
                break;
            }
            this._contentLoaded = true;
        }

        /// <summary>
        /// GetBindingConnector(int connectionId, object target)
        /// </summary>
        [global::System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Windows.UI.Xaml.Build.Tasks"," 10.0.19041.685")]
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
        public global::Windows.UI.Xaml.Markup.IComponentConnector GetBindingConnector(int connectionId, object target)
        {
            global::Windows.UI.Xaml.Markup.IComponentConnector returnValue = null;
            return returnValue;
        }
    }
}

