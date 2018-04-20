package UAClient;

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
import javax.swing.JTextField;
import javax.swing.JTextPane;

/**
 * @author icsd11162 *
 */
public class SIP_ClientGUI implements ActionListener {

	protected JFrame login_frame, pass_frame, error_frame, app_frame;
	protected JLabel bg;

	protected JButton b1, retype, change, exit, call;

	protected JTextField username, pass, address;
	
	protected JTextPane messages;

	protected BufferedImage thumb;

	protected BufferedImage ext, go, go_a, rtp, chg, cl, hngup;

	protected BufferedImage bgd_address, bgd_password, bgd_error, bgd_app;
	

    int posX = 0, posY = 0;

    public static void main (String[] args) {
        SIP_ClientGUI gui = new SIP_ClientGUI();
        gui.app();
        gui.login();
    }

    public SIP_ClientGUI () {
		try {

			thumb = ImageIO.read(new File("assets/logo.png"));

			bgd_address = ImageIO.read(new File("assets/bg_address.png"));
			bgd_password = ImageIO.read(new File("assets/bg_password.png"));
			bgd_error = ImageIO.read(new File("assets/bg_error.png"));
			bgd_app = ImageIO.read(new File("assets/bg_app.png"));

			go = ImageIO.read(new File("assets/go.png"));
			go_a = ImageIO.read(new File("assets/go_a.png"));

			rtp = ImageIO.read(new File("assets/error_retype_bt.png"));
			chg = ImageIO.read(new File("assets/error_change_bt.png"));
			
			cl = ImageIO.read(new File("assets/call.png"));
			hngup = ImageIO.read(new File("assets/hangup.png"));

			ext = ImageIO.read(new File("assets/exit.png"));
		} catch (IOException ex) {
                    Logger.getLogger(SIP_ClientGUI.class.getName()).log(Level.SEVERE, null, ex);
		}

	}

	private void login() {

		// Frame
		login_frame = new JFrame("MultiKAP - netsec16");
		login_frame.setIconImage(thumb);
		login_frame.setDefaultCloseOperation(EXIT_ON_CLOSE);

		login_frame.setResizable(false);
		login_frame.setSize(450, 294);

		login_frame.setUndecorated(true);

		login_frame.setLayout(null);

		login_frame.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent e) {
				posX = e.getX();
				posY = e.getY();
			}
		});

		login_frame.addMouseMotionListener(new MouseAdapter() {
			public void mouseDragged(MouseEvent evt) {
				// sets frame position when mouse dragged
				login_frame.setLocation(evt.getXOnScreen() - posX, evt.getYOnScreen() - posY);

			}
		});

		// Background Image
		bg = new JLabel();
		bg.setSize(450, 294);
		bg.setIcon(new ImageIcon(bgd_address));

		int x = 110;

		username = new JTextField("enter your username");
		username.setBounds(110, 139, 230, 33);
		username.setHorizontalAlignment(JTextField.CENTER);

		// Buttons
		b1 = new JButton();
		b1.setBounds(201, 201, 47, 47);
		b1.setIcon(new ImageIcon(go));
		b1.setPressedIcon(new ImageIcon(go_a));
		b1.setBorderPainted(false);
		b1.setContentAreaFilled(false);

		exit = new JButton();
		exit.setBounds(412, 18, 20, 20);
		exit.setIcon(new ImageIcon(ext));
		exit.setBorderPainted(false);
		exit.setContentAreaFilled(false);

		b1.addActionListener(this);
		exit.addActionListener(this);

		login_frame.add(b1);
		login_frame.add(exit);
		login_frame.add(username);
		login_frame.add(bg);

		login_frame.setVisible(true);

		login_frame.setLocationRelativeTo(null);

	}
	
	private void password() {
		
		// Frame
		pass_frame = new JFrame("MultiKAP - netsec16");
		pass_frame.setIconImage(thumb);
		pass_frame.setDefaultCloseOperation(EXIT_ON_CLOSE);

		pass_frame.setResizable(false);
		pass_frame.setSize(450, 294);

		pass_frame.setUndecorated(true);

		pass_frame.setLayout(null);

		pass_frame.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent e) {
				posX = e.getX();
				posY = e.getY();
			}
		});

		pass_frame.addMouseMotionListener(new MouseAdapter() {
			public void mouseDragged(MouseEvent evt) {
				// sets frame position when mouse dragged
				pass_frame.setLocation(evt.getXOnScreen() - posX, evt.getYOnScreen() - posY);

			}
		});

		// Background Image
		bg = new JLabel();
		bg.setSize(450, 294);
		bg.setIcon(new ImageIcon(bgd_password));

		int x = 110;

		pass = new JTextField("enter your password");
		pass.setBounds(110, 139, 230, 33);
		pass.setHorizontalAlignment(JTextField.CENTER);

		// Buttons
		b1 = new JButton();
		b1.setBounds(201, 201, 47, 47);
		b1.setIcon(new ImageIcon(go));
		b1.setPressedIcon(new ImageIcon(go_a));
		b1.setBorderPainted(false);
		b1.setContentAreaFilled(false);

		exit = new JButton();
		exit.setBounds(412, 18, 20, 20);
		exit.setIcon(new ImageIcon(ext));
		exit.setBorderPainted(false);
		exit.setContentAreaFilled(false);

		b1.addActionListener(this);
		exit.addActionListener(this);

		pass_frame.add(b1);

		pass_frame.add(username);
		pass_frame.add(exit);
		pass_frame.add(bg);

		pass_frame.setVisible(true);

		pass_frame.setLocationRelativeTo(null);
	}

	private void error() {
		// Frame
		error_frame = new JFrame("MultiKAP - netsec16");
		error_frame.setIconImage(thumb);
		error_frame.setDefaultCloseOperation(EXIT_ON_CLOSE);
		error_frame.setResizable(false);
		error_frame.setSize(450, 294);

		error_frame.setUndecorated(true);

		error_frame.setLayout(null);

		error_frame.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent e) {
				posX = e.getX();
				posY = e.getY();
			}
		});

		error_frame.addMouseMotionListener(new MouseAdapter() {
			public void mouseDragged(MouseEvent evt) {
				// sets frame position when mouse dragged
				error_frame.setLocation(evt.getXOnScreen() - posX, evt.getYOnScreen() - posY);

			}
		});

		// Background Image
		bg = new JLabel();
		bg.setSize(450, 294);
		bg.setIcon(new ImageIcon(bgd_error));
		
		retype = new JButton();
		retype.setBounds(186, 146, 70, 37);
		retype.setIcon(new ImageIcon(rtp));
//		retype.setPressedIcon(new ImageIcon(go_a));
		retype.setBorderPainted(false);
		retype.setContentAreaFilled(false);
		
		change = new JButton();
		change.setBounds(186, 201, 73, 35);
		change.setIcon(new ImageIcon(chg));
//		change.setPressedIcon(new ImageIcon(go_a));
		change.setBorderPainted(false);
		change.setContentAreaFilled(false);

		exit = new JButton();
		exit.setBounds(412, 18, 20, 20);
		exit.setIcon(new ImageIcon(ext));
		exit.setBorderPainted(false);
		exit.setContentAreaFilled(false);

		retype.addActionListener(this);
		change.addActionListener(this);
		exit.addActionListener(this);


		error_frame.add(retype);
		error_frame.add(change);
		error_frame.add(exit);
		error_frame.add(bg);

		error_frame.setVisible(true);

		error_frame.setLocationRelativeTo(null);

	}
	
	private void app() {
		// Frame
		app_frame = new JFrame("MultiKAP - netsec16");
		app_frame.setIconImage(thumb);
		app_frame.setDefaultCloseOperation(EXIT_ON_CLOSE);
		app_frame.setResizable(false);
		app_frame.setSize(590, 540);

		app_frame.setUndecorated(true);

		app_frame.setLayout(null);

		app_frame.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent e) {
				posX = e.getX();
				posY = e.getY();
			}
		});

		app_frame.addMouseMotionListener(new MouseAdapter() {
			public void mouseDragged(MouseEvent evt) {
				// sets frame position when mouse dragged
				app_frame.setLocation(evt.getXOnScreen() - posX, evt.getYOnScreen() - posY);

			}
		});

		// Background Image
		bg = new JLabel();
		bg.setSize(590, 540);
		bg.setIcon(new ImageIcon(bgd_app));
		

		messages = new JTextPane();
		messages.setBounds(39, 54, 512, 400);
		
		address = new JTextField("Address");
		address.setBounds(39, 475, 240, 33);
		
		call = new JButton();
		call.setBounds(505, 469, 47, 47);
		call.setIcon(new ImageIcon(cl));
		call.setPressedIcon(new ImageIcon(hngup));
		call.setBorderPainted(false);
		call.setContentAreaFilled(false);
		

		exit = new JButton();
		exit.setBounds(552, 18, 20, 20);
		exit.setIcon(new ImageIcon(ext));
		exit.setBorderPainted(false);
		exit.setContentAreaFilled(false);

		exit.addActionListener(this);


		app_frame.add(call);
		app_frame.add(messages);
		app_frame.add(address);
		app_frame.add(exit);
		app_frame.add(bg);

		app_frame.setVisible(true);

		app_frame.setLocationRelativeTo(null);

	}

	

	@Override
	public void actionPerformed(ActionEvent e) {

		boolean authentication = false;

		if (e.getSource() == b1) {

			
			if (authentication) {
				bg.setIcon(new ImageIcon(bgd_password));
				// frame.repaint();
			} else {
				error();
				login_frame.dispose();
				
				
			}

		}

		
		if (e.getSource() == retype) {
			error_frame.dispose();
			password();
			
		}
		
		if (e.getSource() == change) {
			error_frame.dispose();
			login();
			
		}


		if (e.getSource() == exit) {
			System.exit(1);
		}
	}

}
