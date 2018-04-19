package MultiKAP.GUI;


import MultiKAP.KAProtocols.DHKAP;
import MultiKAP.KAProtocols.ECDHKAP;
import MultiKAP.KAProtocols.EKAP;
import MultiKAP.KAProtocols.STSKAP;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import static javax.swing.JFrame.EXIT_ON_CLOSE;
import javax.swing.JLabel;
/**
 * @author icsd11162 *
 */
public class GUI implements ActionListener {
    
    protected JFrame frame;
    protected JLabel bg;
    
    protected JButton b1, b2, b3, b4, exit;
    
    protected BufferedImage ekap;
    protected BufferedImage dh;
    protected BufferedImage sts;
    protected BufferedImage sup;
    
    protected BufferedImage ekap_a;
    protected BufferedImage dh_a;
    protected BufferedImage sts_a;
    protected BufferedImage sup_a;
    
    protected BufferedImage logo;

    protected BufferedImage bgd;
    
    int posX=0,posY=0;
    
    public GUI() {
        try {
            ekap = ImageIO.read(new File("assets/b1.png"));
            dh = ImageIO.read(new File("assets/b2.png"));
            sts = ImageIO.read(new File("assets/b3.png"));
            sup = ImageIO.read(new File("assets/b4.png"));
        
            ekap_a = ImageIO.read(new File("assets/b1a.png"));
            dh_a = ImageIO.read(new File("assets/b2a.png"));
            sts_a = ImageIO.read(new File("assets/b3a.png"));
            sup_a = ImageIO.read(new File("assets/b4a.png"));
        
            bgd = ImageIO.read(new File("assets/bg.png"));
            
            logo = ImageIO.read(new File("assets/logo.png"));
        } catch (IOException ex) {
            Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
        }
                
        
    }
    private void create() {

                // Frame 
		frame = new JFrame("MultiKAP - netsec16");
                frame.setIconImage(logo);
		frame.setDefaultCloseOperation(EXIT_ON_CLOSE);

		frame.setResizable(false);
		frame.setSize(824, 495);
                
                frame.setUndecorated(true);
		
		frame.setLayout(null);
                
                
                frame.addMouseListener(new MouseAdapter() {
                    public void mousePressed(MouseEvent e)
                    {
                        posX=e.getX();
                        posY=e.getY();
                    }
                });
                
                frame.addMouseMotionListener(new MouseAdapter()
                {
                    public void mouseDragged(MouseEvent evt)
                        {
                            //sets frame position when mouse dragged			
                            frame.setLocation (evt.getXOnScreen()-posX,evt.getYOnScreen()-posY);
                                
                        }
                });
		
                // Background Image
		bg = new JLabel();
		bg.setSize(824, 495);
		bg.setIcon(new ImageIcon(bgd));
		
                
                int x = 110;
                
		// Buttons
		b1 = new JButton();
		b1.setBounds(675, 40, 101, 101);
		b1.setIcon(new ImageIcon(ekap));
                b1.setPressedIcon(new ImageIcon(ekap_a));
                b1.setBorderPainted(false);
                b1.setContentAreaFilled(false);
                
                
                b2 = new JButton();
		b2.setBounds(675, 40 + x, 101, 101);
		b2.setIcon(new ImageIcon(dh));
                b2.setPressedIcon(new ImageIcon(dh_a));
                b2.setBorderPainted(false);
                b2.setContentAreaFilled(false);
                
                
                b3 = new JButton();
		b3.setBounds(675, 40 + 2*x, 101, 101);
		b3.setIcon(new ImageIcon(sts));
                b3.setPressedIcon(new ImageIcon(sts_a));
                b3.setBorderPainted(false);
                b3.setContentAreaFilled(false);
                
                b4 = new JButton();
		b4.setBounds(675, 40 + 3*x, 101, 101);
		b4.setIcon(new ImageIcon(sup));
                b4.setPressedIcon(new ImageIcon(sup_a));
                b4.setBorderPainted(false);
                b4.setContentAreaFilled(false);
                
                exit = new JButton();
		exit.setBounds(783, 10, 31, 31);
                exit.setBorderPainted(false);
                exit.setContentAreaFilled(false);
                
               
		b1.addActionListener(this);
                b2.addActionListener(this);
                b3.addActionListener(this);
                b4.addActionListener(this);
                exit.addActionListener(this);
		
                
		frame.add(b1);
                frame.add(b2);
                frame.add(b3);
                frame.add(b4);
                frame.add(exit);
		frame.add(bg);
		
		frame.setVisible(true);
		
		frame.setLocationRelativeTo(null);
		
		
	}
    
    public static void main(String[] args) {
        GUI gui = new GUI();
        gui.create();
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == b1) {
            try {
                new EKAP().run(System.out);
            } catch (Exception ex) {
                Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        if (e.getSource() == b2) {
            try {
               new DHKAP().run(System.out); 
            } catch (Exception ex) {
                Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        if (e.getSource() == b3) {
            try {
               new STSKAP().run(System.out); 
            } catch (Exception ex) {
                Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        if (e.getSource() == b4) {
            try {
               new ECDHKAP().run(System.out);
            } catch (Exception ex) {
                Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        if (e.getSource() == exit) {
            System.exit(1);
        }
    }


}
