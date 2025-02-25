import gradio as gr
from detector import *

def create_gui():

    # Keep your existing custom CSS
    custom_css = """
/* Base container styling */
.gradio-container {
    /* Soft, warm background with gentle contrast */
    background: linear-gradient(135deg, #f5f0fa 0%, #faf5ff 100%);
    min-height: 100vh;
    padding: 20px;
}

/* Custom header styling */
.custom-h2 {
    font-size: 32px;
    /* Deep blue-violet for headers, easy on eyes */
    color: #4a0080;
    margin-bottom: 30px;
    text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.08);
}

/* Input fields styling */
textarea, input[type="text"] {
    background-color: #ffffff;
    /* Muted purple border with reduced saturation */
    border: 2px solid #8a7bbf;
    border-radius: 12px;
    padding: 12px;
    font-size: 20px;
    /* Dark gray-blue text for optimal readability */
    color: #2d3436;
    transition: all 0.3s ease;
}
textarea:hover, input[type="text"]:hover {
    box-shadow: 0 0 15px rgba(138, 123, 191, 0.2);
}

/* Button styling with modern effects */
button {
    /* Gradient using softer purples */
    background: linear-gradient(135deg, #a77dff 0%, #7950f2 100%);
    color: white;
    border: none;
    border-radius: 8px;
    padding: 12px 24px;
    font-size: 18px;
    cursor: pointer;
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}
button:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(167, 125, 255, 0.2);
}

/* Textbox specific styling */
.gradio-textbox {
    resize: vertical;
    height: auto;
}

/* Live results area */
#live_result {
    background-color: #f8f8f8;
    border-radius: 12px;
    padding: 15px;
    font-family: monospace;
    line-height: 1.5;
}

/* Upload button customization */
.gradio-upload-button {
    margin-top: 15px;
}

/* Responsive design adjustments */
@media (max-width: 768px) {
    textarea, input[type="text"] {
        width: 100%;
        margin-bottom: 15px;
    }
    
    .gradio-row {
        flex-direction: column;
    }
    
    button {
        width: 100%;
        text-align: center;
    }
}
"""
    try:
        # build the GUI
        with gr.Blocks(css=custom_css) as demo:
            gr.Markdown('<h2 class="custom-h2">Port Scanning Alert System</h2>')
            with gr.Row():
                start_btn = gr.Button(value="Start Sniffing")
            with gr.Row():
                with gr.Column():
                    PS_packets_count = gr.Textbox(label="Port Scanning Packets Count", interactive=False)
                with gr.Column():
                    PS_types = gr.Textbox(label="Port Scanning Types", interactive=False)
            with gr.Row():
                with gr.Column():
                    expected_results = gr.Textbox(label="Port Scanning Expected Results")
                with gr.Column():
                    actual_results = gr.Textbox(label="Port Scanning Actual Results", interactive=False)
            with gr.Row():
                calculate_results = gr.Button(value="Calculate Results", interactive=True)
            with gr.Row():
                upload_btn = gr.UploadButton()
            with gr.Row():
                live_result = gr.Textbox(label="Live Results", interactive=False, lines=10)

        start_btn.click(fn=detect_port_scan, inputs='127.0.0.1', outputs=[PS_packets_count, PS_types])
    except Exception as e:
        return {e}
    return demo


if __name__ == "__main__":
    my_screen = create_gui()
    my_screen.launch(share=True)