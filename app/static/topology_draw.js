document.addEventListener('DOMContentLoaded', () => {

    document.getElementById('toggleTopologyBtn').addEventListener('click', function() {
        const topologyTools = document.getElementById('topologyTools');
        const topologyCanvasSection = document.getElementById('topologyCanvasSection');

        // Toggle visibility of the tools and canvas section
        topologyTools.classList.toggle('hidden');
        topologyCanvasSection.classList.toggle('hidden');
    });

    const canvas = document.getElementById('topologyCanvas');
    const ctx = canvas.getContext('2d');

    let selectedTool = null;
    let shapes = [];
    let lines = [];
    let selectedShape = null;
    let selectedLine = null;
    let isDragging = false;
    let dragOffsetX = 0;
    let dragOffsetY = 0;
    let lineStartShape = null;

    function setTool(tool) {
        selectedTool = tool;
        if (tool === 'line') {
            lineStartShape = null;
            selectedLine = null;
        }
    }

    document.getElementById('drawRectangleBtn').addEventListener('click', () => setTool('rectangle'));
    document.getElementById('drawCircleBtn').addEventListener('click', () => setTool('circle'));
    document.getElementById('drawLineBtn').addEventListener('click', () => setTool('line'));
    document.getElementById('drawTextBtn').addEventListener('click', () => setTool('text'));
    document.getElementById('deleteSelectedBtn').addEventListener('click', deleteSelected);
    document.getElementById('clearCanvasBtn').addEventListener('click', clearCanvas);
    document.getElementById('undoBtn').addEventListener('click', undoAction);

    function deleteSelected() {
        if (selectedShape) {
            shapes = shapes.filter(shape => shape !== selectedShape);
            lines = lines.filter(line => line.startShape !== selectedShape && line.endShape !== selectedShape);
            selectedShape = null;
        }
        if (selectedLine) {
            lines = lines.filter(line => line !== selectedLine);
            selectedLine = null;
        }
        drawShapes();
    }

    function clearCanvas() {
        shapes = [];
        lines = [];
        drawShapes();
    }

    let undoStack = [];

    function undoAction() {
        if (undoStack.length > 0) {
            const lastAction = undoStack.pop();
            if (lastAction.type === 'shape') {
                shapes.pop();
            } else if (lastAction.type === 'line') {
                lines.pop();
            }
            drawShapes();
        }
    }

    // Event listeners for drawing on canvas
    let isDrawing = false;
    let startX, startY, endX, endY;

    canvas.addEventListener('mousedown', function(e) {
        startX = e.offsetX;
        startY = e.offsetY;

        selectedShape = getSelectedShape(startX, startY);
        shapes.forEach(shape => shape.selected = false); // Deselect all shapes
        if (selectedTool === 'line' && selectedShape) {
            if (!lineStartShape) {
                lineStartShape = selectedShape;
            } else {
                const line = {
                    startShape: lineStartShape,
                    endShape: selectedShape,
                    selected: false,
                    color: 'black'
                };
                lines.push(line);
                undoStack.push({ type: 'line', line });
                lineStartShape = null;
                drawShapes();
            }
        } else if (selectedShape) {
            selectedShape.selected = true;
            dragOffsetX = startX - selectedShape.x;
            dragOffsetY = startY - selectedShape.y;
            isDragging = true;
        } else if (selectedTool) {
            isDrawing = true;
        } else {
            selectedLine = getSelectedLine(startX, startY);
            if (selectedLine) {
                selectedLine.selected = true;
            }
        }
        drawShapes();
    });

    canvas.addEventListener('mousemove', function(e) {
        if (isDragging && selectedShape) {
            const mouseX = e.offsetX;
            const mouseY = e.offsetY;

            selectedShape.x = mouseX - dragOffsetX;
            selectedShape.y = mouseY - dragOffsetY;
            drawShapes();
        } else if (isDrawing && selectedTool) {
            endX = e.offsetX;
            endY = e.offsetY;

            drawShapes();
            ctx.beginPath();
            if (selectedTool === 'rectangle') {
                ctx.rect(startX, startY, endX - startX, endY - startY);
            } else if (selectedTool === 'circle') {
                ctx.arc(startX, startY, Math.sqrt(Math.pow(endX - startX, 2) + Math.pow(endY - startY, 2)), 0, 2 * Math.PI);
            } else if (selectedTool === 'line') {
                ctx.moveTo(startX, startY);
                ctx.lineTo(endX, endY);
            }
            ctx.stroke();
        }
    });

    canvas.addEventListener('mouseup', function() {
        if (isDragging) {
            isDragging = false;
        } else if (isDrawing) {
            const minDistance = 5; // Minimum distance to create a shape
            const distance = Math.sqrt(Math.pow(endX - startX, 2) + Math.pow(endY - startX, 2));

            if (distance > minDistance) {
                if (selectedTool === 'rectangle') {
                    const rectangle = {
                        type: 'rectangle',
                        x: startX,
                        y: startY,
                        width: endX - startX,
                        height: endY - startY,
                        selected: false,
                        color: 'black',
                    };
                    shapes.push(rectangle);
                    undoStack.push({ type: 'shape', shape: rectangle });
                } else if (selectedTool === 'circle') {
                    const circle = {
                        type: 'circle',
                        x: startX,
                        y: startY,
                        radius: Math.sqrt(Math.pow(endX - startX, 2) + Math.pow(endY - startY, 2)),
                        selected: false,
                        color: 'black',
                    };
                    shapes.push(circle);
                    undoStack.push({ type: 'shape', shape: circle });
                }
            }
            isDrawing = false;
            drawShapes();
        }
    });

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Delete') {
            deleteSelected();
        }
    });

    function drawShapes() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        lines.forEach(line => {
            ctx.beginPath();
            ctx.strokeStyle = line.color || 'black';
            ctx.moveTo(line.startShape.x + (line.startShape.width || line.startShape.radius || 0) / 2,
                       line.startShape.y + (line.startShape.height || line.startShape.radius || 0) / 2);
            ctx.lineTo(line.endShape.x + (line.endShape.width || line.endShape.radius || 0) / 2,
                       line.endShape.y + (line.endShape.height || line.endShape.radius || 0) / 2);
            ctx.stroke();
            if (line.selected) {
                ctx.strokeStyle = 'blue';
                ctx.lineWidth = 2;
                ctx.stroke();
            }
        });
        shapes.forEach(shape => {
            ctx.beginPath();
            ctx.strokeStyle = shape.color || 'black';
            if (shape.type === 'rectangle') {
                ctx.rect(shape.x, shape.y, shape.width, shape.height);
            } else if (shape.type === 'circle') {
                ctx.arc(shape.x, shape.y, shape.radius, 0, 2 * Math.PI);
            }
            ctx.stroke();
            if (shape.selected) {
                ctx.strokeStyle = 'blue';
                ctx.lineWidth = 2;
                ctx.strokeRect(shape.x - 5, shape.y - 5, shape.width + 10, shape.height + 10); // Draw a selection box
            }
        });
    }

    canvas.addEventListener('contextmenu', function(e) {
        e.preventDefault();
        const mouseX = e.offsetX;
        const mouseY = e.offsetY;

        shapes.forEach(shape => (shape.selected = false)); // Deselect all shapes
        selectedShape = getSelectedShape(mouseX, mouseY);
        selectedLine = getSelectedLine(mouseX, mouseY);
        if (selectedShape) {
            selectedShape.selected = true;
            showContextMenu(e.pageX, e.pageY, selectedShape);
        } else if (selectedLine) {
            selectedLine.selected = true;
            showLineContextMenu(e.pageX, e.pageY, selectedLine);
        }

        drawShapes();
    });

    function getSelectedShape(x, y) {
        return shapes.find(shape => isInsideShape(shape, x, y));
    }

    function getSelectedLine(x, y) {
        return lines.find(line => isOnLine(line, x, y));
    }

    function isInsideShape(shape, x, y) {
        if (shape.type === 'rectangle') {
            return x > shape.x && x < shape.x + shape.width && y > shape.y && y < shape.y + shape.height;
        } else if (shape.type === 'circle') {
            const dx = x - shape.x;
            const dy = y - shape.y;
            return dx * dx + dy * dy <= shape.radius * shape.radius;
        }
        return false;
    }

    function isOnLine(line, x, y) {
        const x1 = line.startShape.x + (line.startShape.width || line.startShape.radius || 0) / 2;
        const y1 = line.startShape.y + (line.startShape.height || line.startShape.radius || 0) / 2;
        const x2 = line.endShape.x + (line.endShape.width || line.endShape.radius || 0) / 2;
        const y2 = line.endShape.y + (line.endShape.height || line.endShape.radius || 0) / 2;
        const distance = Math.abs((y2 - y1) * x - (x2 - x1) * y + x2 * y1 - y2 * x1) / Math.sqrt(Math.pow(y2 - y1, 2) + Math.pow(x2 - x1, 2));
        return distance < 5;
    }

    function showContextMenu(x, y, shape) {
        const menu = document.createElement('div');
        menu.style.position = 'absolute';
        menu.style.top = `${y}px`;
        menu.style.left = `${x}px`;
        menu.style.backgroundColor = '#ccc';
        menu.style.padding = '10px';
        menu.style.border = '1px solid #000';
        menu.innerHTML = `
            <button id="deleteShapeBtn">Delete</button>
            <button id="colorPickerBtn">Change Color</button>
            <button id="resizeBtn">Resize</button>
            <button id="cloneBtn">Clone</button>
        `;

        document.body.appendChild(menu);

        document.getElementById('deleteShapeBtn').addEventListener('click', () => {
            deleteShape(shapes.indexOf(shape));
            document.body.removeChild(menu);
        });

        document.getElementById('colorPickerBtn').addEventListener('click', () => {
            openColorPicker(shapes.indexOf(shape));
            document.body.removeChild(menu);
        });

        document.getElementById('resizeBtn').addEventListener('click', () => {
            startResizing(shapes.indexOf(shape));
            document.body.removeChild(menu);
        });

        document.getElementById('cloneBtn').addEventListener('click', () => {
            cloneShape(shapes.indexOf(shape));
            document.body.removeChild(menu);
        });

        menu.addEventListener('mouseleave', function() {
            document.body.removeChild(menu);
        });
    }

    function showLineContextMenu(x, y, line) {
        const menu = document.createElement('div');
        menu.style.position = 'absolute';
        menu.style.top = `${y}px`;
        menu.style.left = `${x}px`;
        menu.style.backgroundColor = '#ccc';
        menu.style.padding = '10px';
        menu.style.border = '1px solid #000';
        menu.innerHTML = `
            <button id="deleteLineBtn">Delete Line</button>
        `;

        document.body.appendChild(menu);

        document.getElementById('deleteLineBtn').addEventListener('click', () => {
            lines = lines.filter(l => l !== line);
            document.body.removeChild(menu);
            drawShapes();
        });

        menu.addEventListener('mouseleave', function() {
            document.body.removeChild(menu);
        });
    }

    function cloneShape(index) {
        const shape = shapes[index];
        const clone = { ...shape, x: shape.x + 20, y: shape.y + 20, selected: false };
        shapes.push(clone);
        undoStack.push({ type: 'shape', shape: clone });
        drawShapes();
    }

    function deleteShape(index) {
        shapes.splice(index, 1);
        lines = lines.filter(line => line.startShape !== selectedShape && line.endShape !== selectedShape);
        drawShapes();
    }

    function openColorPicker(index) {
        const color = prompt('Enter a color:', shapes[index].color || 'black');
        if (color) {
            shapes[index].color = color;
            drawShapes();
        }
    }

    function startResizing(index) {
        const shape = shapes[index];
        isDrawing = true;
        isResizing = true;
        selectedTool = 'resize';

        function resize(e) {
            const newX = e.offsetX;
            const newY = e.offsetY;

            if (shape.type === 'rectangle') {
                shape.width = newX - shape.x;
                shape.height = newY - shape.y;
            } else if (shape.type === 'circle') {
                shape.radius = Math.sqrt(Math.pow(newX - shape.x, 2) + Math.pow(newY - shape.y, 2));
            }

            drawShapes();
        }

        canvas.addEventListener('mousemove', resize);
        canvas.addEventListener('mouseup', function stopResizing() {
            isDrawing = false;
            isResizing = false;
            canvas.removeEventListener('mousemove', resize);
        }, { once: true });
    }
});
