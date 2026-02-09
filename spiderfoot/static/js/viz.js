// Takes an object in the form of:
// { name: "blah", children: [ { name: "blah 2", children: [ ... ] } ] }
// and counts the number of objects without children
function sf_viz_countTailNodes(arg) {
    var data = arg;
    var count = 0;

    for (var i = 0; i < data.length; i++) {
        for (var p in data[i]) {
            if (p == "children" && data[i].children == null) {
                count++;
                continue;
            }
            if (p == "children" && data[i].children != null) {
                count += sf_viz_countTailNodes(data[i].children);
            }
        }
    }

    return count;
}

// As above but counts the total number of objects
function sf_viz_countTotalNodes(arg) {
    var data = arg;
    var count = 0;

    for (var i = 0; i < data.length; i++) {
        for (var p in data[i]) {
            if (p == "name") {
                count++;
                continue;
            }
            if (p == "children" && data[i].children != null) {
                count += sf_viz_countTotalNodes(data[i].children);
            }
        }
    }

    return count;
}

// As above but counts the highest number of levels
function sf_viz_countLevels(arg, levelsDeep, maxLevels) {
    var data = arg;
    var levels = levelsDeep;
    var max = maxLevels;

    for (var i = 0; i < data.length; i++) {
        for (var p in data[i]) {
            // We've hit a member with children..
            if (p == "children" && data[i].children != null) {
                levels++;
                arr = sf_viz_countLevels(data[i].children, levels, max);
                levels = arr[0];
                max = arr[1];
            }

            if (p == "children" && data[i].children == null) {
                if (levels > max) {
                    //alert("max = " + levels);
                    max = levels;
                }
            }
        }

        // Reset to the level we're at as we iterate through the next child.
        levels = levelsDeep;
    }

    return [ levels, max ];
}

function sf_viz_vbar(targetId, gdata) {
    var margin = {top: 20, right: 20, bottom: 220, left: 60},
        width = 1100 - margin.left - margin.right,
        height = 520 - margin.top - margin.bottom;

    var formatPercent = d3.format(".0%");

    var x = d3.scale.ordinal()
        .rangeRoundBands([0, width], .1);

    var y = d3.scale.linear()
        .range([height, 0]);

    var xAxis = d3.svg.axis()
        .scale(x)
        .orient("bottom");

    var yAxis = d3.svg.axis()
        .scale(y)
        .orient("left")

/*    var tip = d3.tip()
      .attr('class', 'd3-tip')
      .offset([-10, 0])
      .html(function(d) {
        return "<strong>counter Elements:</strong> <span style='color:red'>" + d.counter + "</span>";
      })
*/
    var svg = d3.select(targetId).append("svg")
        .attr("width", width + margin.left + margin.right)
        .attr("height", height + margin.top + margin.bottom)
      .append("g")
        .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

 //   svg.call(tip);

    data = new Array();
    for (i = 0; i < gdata.length; i++) {
        data[i] = sf_viz_vbar_type(gdata[i])
    }
    x.domain(data.map(function(d) { return d.name; }));
    y.domain([0, d3.max(data, function(d) { return d.pct*100; })]);

    svg.append("g")
        .attr("class", "x axis")
        .attr("transform", "translate(0," + height + ")")
        .call(xAxis)
        .selectAll("text")
            .style("text-anchor", "end")
            .attr("dx", "-.8em")
            .attr("dy", ".15em")
            .attr("transform", function(d) {
                return "rotate(-45)" 
            });

    svg.append("g")
        .attr("class", "y axis")
        .call(yAxis)
      .append("text")
        .attr("class", "y-axis-label")
        .attr("transform", "rotate(-90)")
        .attr("y", 6)
        .attr("dy", "-50px")
        .style("text-anchor", "end")
        .style("text-transform", "uppercase")
        .style("letter-spacing", "1px")
        .style("font-size", "11px")
        .text("PERCENTAGE OF UNIQUE ELEMENTS");

    svg.selectAll(".bar")
        .data(data)
      .enter().append("rect")
        .attr("class", "bar")
        .attr("x", function(d) { return x(d.name); })
        .attr("width", x.rangeBand())
        .attr("y", function(d) { return y(d.pct*100); })
        .attr("height", function(d) { return height - y(d.pct*100); })
        .on('mousedown', function(d) { showToolTip(" ",0,0,false); d.link(d); } )
        .on("mouseover", function(d, i) {
            showToolTip(buildPopupMessage(d), d3.event.pageX+10, d3.event.pageY+10,true);
        })
        .on("mouseout", function() {
            showToolTip(" ",0,0,false);
        });


    function buildPopupMessage(data) {
        message = "<table>";
        message += "<tr><td><b>TYPE:</b></td><td>" + data.name.toUpperCase() + "</td></tr>";
        message += "<tr><td><b>UNIQUE:</b></td><td>" + data.counter + "</td></tr>";
        message += "<tr><td><b>TOTAL:</b></td><td>" + data.total+ "</td></tr>";
        message += "</table>";
        return message;
    }

    function showToolTip(pMessage,pX,pY,pShow) {
        if (typeof(tooltipDivID)=="undefined") {
            tooltipDivID =$('<div id="messageToolTipDiv" style="position:absolute;display:block;z-index:10000;border:2px solid black;background-color:rgba(0,0,0,0.8);margin:auto;padding:3px 5px 3px 5px;color:white;font-size:12px;font-family:arial;border-radius: 5px;vertical-align: middle;text-align: center;min-width:50px;overflow:auto;"></div>');
            $('body').append(tooltipDivID);
        }
        if (!pShow) { tooltipDivID.hide(); return;}
        tooltipDivID.html(pMessage);
        tooltipDivID.css({top:pY,left:pX});
        tooltipDivID.show();
    }
}

function sf_viz_vbar_type(d) {
      d.pct = +d.pct;
      return d;
}

function sf_viz_dendrogram(targetId, data) {
    var plotData = data['tree'];
    var dataMap = data['data'];
    var scanId = data['scanId'];
    var width = sf_viz_countLevels([plotData], 0, 0)[1] * 170;
    var height = sf_viz_countTailNodes([plotData]) * 20;

    if (width < 600) {
        width = 600;
    }
    if (height < 600) {
        height = 600;
    }

    var cluster = d3.layout.cluster()
        .size([height, width - 160]);

    var diagonal = d3.svg.diagonal()
        .projection(function(d) { return [d.y, d.x]; });

    var svg = d3.select(targetId).append("svg")
        .attr("width", width)
        .attr("height", height)
        .append("g")
        .attr("transform", "translate(40,0)");

    var nodes = cluster.nodes(plotData),
        links = cluster.links(nodes);

    var link = svg.selectAll(".link")
        .data(links)
        .enter().append("path")
        .attr("class", "dend-link")
        .attr("d", diagonal);

    // Track currently selected node for path highlighting
    var selectedNode = null;
    // Track which node has the info panel open
    var infoPanelNode = null;
    // Track nodes marked as FP in this session (for undo capability)
    var sessionFpNodes = {};
    // Track nodes marked as Validated in this session
    var sessionValidatedNodes = {};
    // Store last panel position for updates
    var lastPanelX = 100;
    var lastPanelY = 100;

    // Function to get path from node to root
    function getPathToRoot(node) {
        var path = [];
        var current = node;
        while (current) {
            path.push(current);
            current = current.parent;
        }
        return path;
    }

    // Function to get all descendants of a node (children, grandchildren, etc.)
    function getDescendants(node) {
        var descendants = [];
        function traverse(n) {
            if (n.children) {
                n.children.forEach(function(child) {
                    descendants.push(child);
                    traverse(child);
                });
            }
        }
        traverse(node);
        return descendants;
    }

    // Function to highlight path
    function highlightPath(node) {
        // Clear previous highlights
        svg.selectAll(".dend-link").classed("dend-link-highlighted", false).classed("dend-link-dimmed", false);
        svg.selectAll(".dend-node").classed("dend-node-selected", false).classed("dend-node-path", false).classed("dend-node-dimmed", false);
        d3.select(targetId).classed("path-active", false);

        if (selectedNode === node) {
            // Clicking same node deselects
            selectedNode = null;
            return;
        }

        selectedNode = node;
        var pathNodes = getPathToRoot(node);

        // Mark container as having active path selection
        d3.select(targetId).classed("path-active", true);

        // Highlight nodes in path, dim others
        svg.selectAll(".dend-node").each(function(d) {
            var inPath = pathNodes.indexOf(d) !== -1;
            d3.select(this).classed("dend-node-path", inPath);
            d3.select(this).classed("dend-node-selected", d === node);
            d3.select(this).classed("dend-node-dimmed", !inPath);
        });

        // Highlight links in path, dim others
        svg.selectAll(".dend-link").each(function(d) {
            var sourceInPath = pathNodes.indexOf(d.source) !== -1;
            var targetInPath = pathNodes.indexOf(d.target) !== -1;
            var linkInPath = sourceInPath && targetInPath;
            d3.select(this).classed("dend-link-highlighted", linkInPath);
            d3.select(this).classed("dend-link-dimmed", !linkInPath);
        });
    }

    // Mark a node as false positive (persists to future scans)
    function markAsFalsePositive(nodeName, setFp, ignoreParent) {
        var nodeData = dataMap[nodeName];
        if (!nodeData || !nodeData[8]) {
            console.error("No node data or hash for:", nodeName);
            alert("Cannot mark this item - no data available");
            return;
        }

        var hash = nodeData[8];
        var fpValue = setFp ? "1" : "0";

        console.log("Marking FP:", nodeName, "hash:", hash, "fp:", fpValue, "scanId:", scanId);

        $.ajax({
            url: docroot + '/resultsetfppersist',
            type: 'GET',
            data: {
                id: scanId,
                resultids: JSON.stringify([hash]),
                fp: fpValue,
                persist: "1"  // Apply to future scans as well
            },
            success: function(response) {
                console.log("FP response:", response);
                var result;
                try {
                    result = typeof response === 'string' ? JSON.parse(response) : response;
                } catch (e) {
                    console.error("Failed to parse response:", e);
                    alert("Error parsing server response");
                    return;
                }

                if (result[0] === "SUCCESS") {
                    // Find the clicked node and all its descendants
                    var clickedNode = null;
                    var descendantNames = [];
                    svg.selectAll(".dend-node").each(function(d) {
                        if (d.name === nodeName) {
                            clickedNode = d;
                        }
                    });

                    // Get all descendant node names (unless ignoreParent is true)
                    if (clickedNode && !ignoreParent) {
                        var descendants = getDescendants(clickedNode);
                        descendantNames = descendants.map(function(d) { return d.name; });
                    }

                    if (setFp) {
                        // Mark the node and all descendants as FP
                        sessionFpNodes[nodeName] = true;
                        // Clear any validated marking
                        delete sessionValidatedNodes[nodeName];
                        descendantNames.forEach(function(name) {
                            sessionFpNodes[name] = true;
                            delete sessionValidatedNodes[name];
                        });

                        // Mark all nodes visually as FP (red)
                        svg.selectAll(".dend-node").each(function(d) {
                            if (d.name === nodeName || descendantNames.indexOf(d.name) !== -1) {
                                d3.select(this).classed("dend-node-fp", true);
                                d3.select(this).classed("dend-node-validated", false);
                            }
                        });

                        // Also highlight the links to descendants
                        svg.selectAll(".dend-link").each(function(linkData) {
                            var sourceIsFp = linkData.source.name === nodeName || descendantNames.indexOf(linkData.source.name) !== -1;
                            var targetIsFp = linkData.target.name === nodeName || descendantNames.indexOf(linkData.target.name) !== -1;
                            if (sourceIsFp && targetIsFp) {
                                d3.select(this).classed("dend-link-fp", true);
                                d3.select(this).classed("dend-link-validated", false);
                            }
                        });
                    } else {
                        // Remove FP marking from node and all descendants
                        delete sessionFpNodes[nodeName];
                        descendantNames.forEach(function(name) {
                            delete sessionFpNodes[name];
                        });

                        // Remove FP visual marking
                        svg.selectAll(".dend-node").each(function(d) {
                            if (d.name === nodeName || descendantNames.indexOf(d.name) !== -1) {
                                d3.select(this).classed("dend-node-fp", false);
                            }
                        });

                        // Remove FP link styling
                        svg.selectAll(".dend-link").each(function(linkData) {
                            var sourceWasFp = linkData.source.name === nodeName || descendantNames.indexOf(linkData.source.name) !== -1;
                            var targetWasFp = linkData.target.name === nodeName || descendantNames.indexOf(linkData.target.name) !== -1;
                            if (sourceWasFp && targetWasFp) {
                                d3.select(this).classed("dend-link-fp", false);
                            }
                        });
                    }
                    // Update the info panel if it's still open
                    if (infoPanelNode && infoPanelNode.name === nodeName) {
                        updateInfoPanel(infoPanelNode);
                    }
                } else if (result[0] === "WARNING") {
                    alert(result[1]);
                } else {
                    alert("Error setting false positive: " + (result[1] || "Unknown error"));
                }
            },
            error: function(xhr, status, error) {
                console.error("AJAX error:", status, error, xhr.responseText);
                alert("Failed to communicate with server: " + error);
            }
        });
    }

    // Mark a node as validated (persists to future scans)
    function markAsValidated(nodeName, setValidated, ignoreParent) {
        var nodeData = dataMap[nodeName];
        if (!nodeData || !nodeData[8]) {
            console.error("No node data or hash for:", nodeName);
            alert("Cannot mark this item - no data available");
            return;
        }

        var hash = nodeData[8];
        var fpValue = setValidated ? "2" : "0";  // 2 = validated, 0 = unset

        console.log("Marking Validated:", nodeName, "hash:", hash, "validated:", setValidated, "scanId:", scanId);

        $.ajax({
            url: docroot + '/resultsetfppersist',
            type: 'GET',
            data: {
                id: scanId,
                resultids: JSON.stringify([hash]),
                fp: fpValue,
                persist: "1"
            },
            success: function(response) {
                console.log("Validated response:", response);
                var result;
                try {
                    result = typeof response === 'string' ? JSON.parse(response) : response;
                } catch (e) {
                    console.error("Failed to parse response:", e);
                    alert("Error parsing server response");
                    return;
                }

                if (result[0] === "SUCCESS") {
                    var clickedNode = null;
                    var descendantNames = [];
                    svg.selectAll(".dend-node").each(function(d) {
                        if (d.name === nodeName) {
                            clickedNode = d;
                        }
                    });

                    if (clickedNode && !ignoreParent) {
                        var descendants = getDescendants(clickedNode);
                        descendantNames = descendants.map(function(d) { return d.name; });
                    }

                    if (setValidated) {
                        // Mark the node and descendants as validated
                        sessionValidatedNodes[nodeName] = true;
                        // Clear any FP marking
                        delete sessionFpNodes[nodeName];
                        descendantNames.forEach(function(name) {
                            sessionValidatedNodes[name] = true;
                            delete sessionFpNodes[name];
                        });

                        // Mark visually as validated (blue)
                        svg.selectAll(".dend-node").each(function(d) {
                            if (d.name === nodeName || descendantNames.indexOf(d.name) !== -1) {
                                d3.select(this).classed("dend-node-validated", true);
                                d3.select(this).classed("dend-node-fp", false);
                            }
                        });

                        svg.selectAll(".dend-link").each(function(linkData) {
                            var sourceIsVal = linkData.source.name === nodeName || descendantNames.indexOf(linkData.source.name) !== -1;
                            var targetIsVal = linkData.target.name === nodeName || descendantNames.indexOf(linkData.target.name) !== -1;
                            if (sourceIsVal && targetIsVal) {
                                d3.select(this).classed("dend-link-validated", true);
                                d3.select(this).classed("dend-link-fp", false);
                            }
                        });
                    } else {
                        // Remove validated marking
                        delete sessionValidatedNodes[nodeName];
                        descendantNames.forEach(function(name) {
                            delete sessionValidatedNodes[name];
                        });

                        svg.selectAll(".dend-node").each(function(d) {
                            if (d.name === nodeName || descendantNames.indexOf(d.name) !== -1) {
                                d3.select(this).classed("dend-node-validated", false);
                            }
                        });

                        svg.selectAll(".dend-link").each(function(linkData) {
                            var sourceWasVal = linkData.source.name === nodeName || descendantNames.indexOf(linkData.source.name) !== -1;
                            var targetWasVal = linkData.target.name === nodeName || descendantNames.indexOf(linkData.target.name) !== -1;
                            if (sourceWasVal && targetWasVal) {
                                d3.select(this).classed("dend-link-validated", false);
                            }
                        });
                    }
                    // Update the info panel if still open
                    if (infoPanelNode && infoPanelNode.name === nodeName) {
                        updateInfoPanel(infoPanelNode);
                    }
                } else if (result[0] === "WARNING") {
                    alert(result[1]);
                } else {
                    alert("Error setting validated: " + (result[1] || "Unknown error"));
                }
            },
            error: function(xhr, status, error) {
                console.error("AJAX error:", status, error, xhr.responseText);
                alert("Failed to communicate with server: " + error);
            }
        });
    }

    // Update info panel content (preserves position)
    function updateInfoPanel(d) {
        var nodeData = dataMap[d.name];
        var isFp = sessionFpNodes[d.name] || false;
        var isValidated = sessionValidatedNodes[d.name] || false;
        // Use stored position instead of d3.event (which won't exist in AJAX callback)
        showInfoPanel(buildInfoPanelMessage(nodeData, d.name, isFp, isValidated), lastPanelX, lastPanelY, true);
    }

    var node = svg.selectAll(".node")
        .data(nodes)
        .enter().append("g")
        .attr("class", "dend-node")
        .attr("transform", function(d) { return "translate(" + d.y + "," + d.x + ")"; })
        .on("click", function(d) {
            d3.event.stopPropagation();

            // If clicking the same node with info panel open, close it and deselect
            if (infoPanelNode === d) {
                hideInfoPanel();
                infoPanelNode = null;
                selectedNode = null;
                svg.selectAll(".dend-link").classed("dend-link-highlighted", false).classed("dend-link-dimmed", false);
                svg.selectAll(".dend-node").classed("dend-node-selected", false).classed("dend-node-path", false).classed("dend-node-dimmed", false);
                d3.select(targetId).classed("path-active", false);
                return;
            }

            // Highlight path
            highlightPath(d);

            // Show persistent info panel
            infoPanelNode = d;
            var nodeData = dataMap[d.name];
            var isFp = sessionFpNodes[d.name] || false;
            var isValidated = sessionValidatedNodes[d.name] || false;
            // Store position for later updates
            lastPanelX = d3.event.pageX + 10;
            lastPanelY = d3.event.pageY + 10;
            showInfoPanel(buildInfoPanelMessage(nodeData, d.name, isFp, isValidated), lastPanelX, lastPanelY, true);
        })
        .on("mouseover", function(d, i) {
            d3.select(this).classed("dend-node-hover", true);
            // Only show hover tooltip if no info panel is open
            if (!infoPanelNode) {
                showToolTip(buildPopupMessage(dataMap[d.name]), d3.event.pageX+10, d3.event.pageY+10, true);
            }
        })
        .on("mouseout", function() {
            d3.select(this).classed("dend-node-hover", false);
            if (!infoPanelNode) {
                showToolTip(" ", 0, 0, false);
            }
        });

    // Click on background to deselect and close info panel
    d3.select(targetId).on("click", function() {
        selectedNode = null;
        infoPanelNode = null;
        hideInfoPanel();
        svg.selectAll(".dend-link").classed("dend-link-highlighted", false).classed("dend-link-dimmed", false);
        svg.selectAll(".dend-node").classed("dend-node-selected", false).classed("dend-node-path", false).classed("dend-node-dimmed", false);
        d3.select(targetId).classed("path-active", false);
    });

    node.append("circle")
        .attr("r", 4.5);

    node.append("text")
        .attr("dx", function(d) {
            if (d.depth == 0) {
                return 50;
            }

            return d.children ? -8 : 8;
        })
        .attr("dy", 3)
        .style("text-anchor", function(d) { return d.children ? "end" : "start"; })
        .text(function(d) {
            if (dataMap[d.name][1].length > 20) {
                return sf.remove_sfurltag(dataMap[d.name][1].substring(0, 20) + "...");
            } else {
                return sf.remove_sfurltag(dataMap[d.name][1]);
            }
        });

    d3.select(targetId).style("height", height + "px");

    // Simple hover tooltip (brief info)
    function buildPopupMessage(data) {
        var displayData = data[1];
        if (displayData.length > 200) {
            displayData = displayData.substring(0, 200) + "...";
        }
        displayData = displayData.replace(/</g, "&lt;").replace(/>/g, "&gt;");
        // Use explicit white text colors to override global CSS rules
        var message = "<table style='color:white;'>";
        message += "<tr><td style='color:white;'><b>Type:</b></td><td style='color:white;'>" + data[10] + "</td></tr>";
        message += "<tr><td style='color:white;'><b>Source Module:</b></td><td style='color:white;'>" + data[3] + "</td></tr>";
        message += "<tr><td style='color:white;'><b>Data:</b></td><td style='color:white;'><pre style='color:#1f2937;background:#e5e7eb;padding:4px 8px;border-radius:4px;margin:0;'>" + sf.remove_sfurltag(displayData);
        message += "</pre></td></tr>";
        message += "</table>";
        message += "<div style='font-size:10px;color:#888;margin-top:5px;'>Click for more options</div>";
        return message;
    }

    // Persistent info panel with FP and Validate buttons (detailed info + actions)
    function buildInfoPanelMessage(data, nodeName, isFp, isValidated) {
        var displayData = data[1];
        if (displayData.length > 300) {
            displayData = displayData.substring(0, 300) + "...";
        }
        displayData = displayData.replace(/</g, "&lt;").replace(/>/g, "&gt;");

        // Detect dark mode for styling
        var isDarkMode = document.body.classList.contains('dark-mode') ||
                         document.documentElement.getAttribute('data-theme') === 'dark' ||
                         window.matchMedia('(prefers-color-scheme: dark)').matches;

        var textColor = isDarkMode ? '#f3f4f6' : '#1f2937';
        var labelColor = isDarkMode ? '#9ca3af' : '#4b5563';
        var preBackground = isDarkMode ? 'rgba(55, 65, 81, 0.5)' : 'rgba(243, 244, 246, 1)';
        var preTextColor = isDarkMode ? '#e5e7eb' : '#1f2937';
        var borderColor = isDarkMode ? 'rgba(75, 85, 99, 0.5)' : 'rgba(209, 213, 219, 1)';

        // Close button at top right
        var message = "<div style='position:relative;text-align:left;color:" + textColor + ";'>";
        message += "<button onclick='window.dendroCloseInfoPanel()' style='position:absolute;top:-8px;right:-8px;background:#6b7280;color:white;border:none;width:24px;height:24px;border-radius:50%;cursor:pointer;font-size:14px;line-height:1;'>&times;</button>";
        message += "<table style='margin-bottom:10px;color:" + textColor + ";'>";
        message += "<tr><td style='color:" + labelColor + ";padding-right:10px;'><b>Type:</b></td><td style='color:" + textColor + ";'>" + data[10] + "</td></tr>";
        message += "<tr><td style='color:" + labelColor + ";padding-right:10px;'><b>Source Module:</b></td><td style='color:" + textColor + ";'>" + data[3] + "</td></tr>";
        message += "<tr><td style='color:" + labelColor + ";padding-right:10px;vertical-align:top;'><b>Data:</b></td><td><pre style='max-width:300px;overflow:auto;background:" + preBackground + ";color:" + preTextColor + ";padding:8px;border-radius:4px;border:1px solid " + borderColor + ";margin:0;'>" + sf.remove_sfurltag(displayData) + "</pre></td></tr>";
        message += "</table>";

        // Don't show buttons for synthetic nodes (like "Discovery Paths")
        if (data[8] && data[8] !== 'discovery_paths') {
            message += "<div style='border-top:1px solid " + borderColor + ";padding-top:10px;margin-top:5px;display:flex;flex-wrap:wrap;gap:8px;'>";

            var escapedName = nodeName.replace(/"/g, '\\"');

            if (isFp) {
                // Currently marked as False Positive - show unmark options
                message += "<span style='display:inline-block;background:#ea580c;color:white;padding:6px 12px;border-radius:4px;font-weight:600;font-size:11px;'>FALSE POSITIVE</span>";
                message += "<button onclick='window.dendroUnsetFp(\"" + escapedName + "\", false)' style='background:#6b7280;color:white;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:600;'>UNMARK FP</button>";
                message += "<button onclick='window.dendroUnsetFp(\"" + escapedName + "\", true)' style='background:#4b5563;color:white;border:none;padding:6px 10px;border-radius:4px;cursor:pointer;font-size:10px;'>UNMARK - IGNORE PARENT</button>";
            } else if (isValidated) {
                // Currently marked as Validated - show unmark options
                message += "<span style='display:inline-block;background:#2563eb;color:white;padding:6px 12px;border-radius:4px;font-weight:600;font-size:11px;'>VALIDATED</span>";
                message += "<button onclick='window.dendroUnsetValidated(\"" + escapedName + "\", false)' style='background:#6b7280;color:white;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:600;'>UNVALIDATE</button>";
                message += "<button onclick='window.dendroUnsetValidated(\"" + escapedName + "\", true)' style='background:#4b5563;color:white;border:none;padding:6px 10px;border-radius:4px;cursor:pointer;font-size:10px;'>UNMARK - IGNORE PARENT</button>";
            } else {
                // Not marked - show both action buttons
                message += "<button onclick='window.dendroSetFp(\"" + escapedName + "\")' style='background:#ea580c;color:white;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-weight:600;font-size:11px;'>FALSE POSITIVE</button>";
                message += "<button onclick='window.dendroSetValidated(\"" + escapedName + "\")' style='background:#2563eb;color:white;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-weight:600;font-size:11px;'>VALIDATE</button>";
            }
            message += "</div>";
        }
        message += "</div>";
        return message;
    }

    // Expose FP functions globally for button onclick
    window.dendroSetFp = function(nodeName) {
        markAsFalsePositive(nodeName, true);
    };
    window.dendroUnsetFp = function(nodeName, ignoreParent) {
        markAsFalsePositive(nodeName, false, ignoreParent);
    };
    // Expose Validate functions globally for button onclick
    window.dendroSetValidated = function(nodeName) {
        markAsValidated(nodeName, true);
    };
    window.dendroUnsetValidated = function(nodeName, ignoreParent) {
        markAsValidated(nodeName, false, ignoreParent);
    };
    window.dendroCloseInfoPanel = function() {
        infoPanelNode = null;
        hideInfoPanel();
        // Also clear path highlighting
        selectedNode = null;
        svg.selectAll(".dend-link").classed("dend-link-highlighted", false).classed("dend-link-dimmed", false);
        svg.selectAll(".dend-node").classed("dend-node-selected", false).classed("dend-node-path", false).classed("dend-node-dimmed", false);
        d3.select(targetId).classed("path-active", false);
    };

    function showToolTip(pMessage, pX, pY, pShow) {
        if (typeof(tooltipDivID) == "undefined") {
            tooltipDivID = $('<div id="messageToolTipDiv" style="position:absolute;display:block;z-index:10000;border:2px solid black;background-color:rgba(0,0,0,0.9);margin:auto;padding:8px 12px;color:white;font-size:12px;font-family:arial;border-radius:5px;vertical-align:middle;text-align:center;min-width:50px;overflow:auto;max-width:400px;"></div>');
            $('body').append(tooltipDivID);
        }
        if (!pShow) { tooltipDivID.hide(); return; }
        tooltipDivID.html(pMessage);
        tooltipDivID.css({top: pY, left: pX});
        tooltipDivID.show();
    }

    function showInfoPanel(pMessage, pX, pY, pShow) {
        // Detect dark mode
        var isDarkMode = document.body.classList.contains('dark-mode') ||
                         document.documentElement.getAttribute('data-theme') === 'dark' ||
                         window.matchMedia('(prefers-color-scheme: dark)').matches;

        var bgColor = isDarkMode ? 'rgba(17, 24, 39, 0.98)' : 'rgba(255, 255, 255, 0.98)';
        var textColor = isDarkMode ? '#f3f4f6' : '#1f2937';
        var borderColor = isDarkMode ? '#06b6d4' : '#0891b2';
        var shadowColor = isDarkMode ? 'rgba(6, 182, 212, 0.3)' : 'rgba(8, 145, 178, 0.2)';

        if (typeof(infoPanelDivID) == "undefined") {
            infoPanelDivID = $('<div id="infoPanelDiv" class="dendro-info-panel"></div>');
            $('body').append(infoPanelDivID);
        }
        if (!pShow) { infoPanelDivID.hide(); return; }

        // Update styles based on theme
        infoPanelDivID.css({
            'position': 'absolute',
            'display': 'block',
            'z-index': '10001',
            'border': '2px solid ' + borderColor,
            'background-color': bgColor,
            'margin': 'auto',
            'padding': '12px 16px',
            'color': textColor,
            'font-size': '12px',
            'font-family': 'arial',
            'border-radius': '8px',
            'vertical-align': 'middle',
            'min-width': '200px',
            'max-width': '450px',
            'box-shadow': '0 0 20px ' + shadowColor
        });

        // Hide hover tooltip when showing info panel
        if (typeof(tooltipDivID) != "undefined") {
            tooltipDivID.hide();
        }
        infoPanelDivID.html(pMessage);
        infoPanelDivID.css({top: pY, left: pX});
        infoPanelDivID.show();
    }

    function hideInfoPanel() {
        if (typeof(infoPanelDivID) != "undefined") {
            infoPanelDivID.hide();
        }
    }
}


// Produces a bubble diagram enabling visually comparing size of
// data points.
// plotData should be an array of the items you want to plot
function sf_viz_bubble(targetId, plotData) { 
    var diameter = 900,
        format = d3.format(",d"),
        color = d3.scale.category20c();

    var bubble = d3.layout.pack()
        .sort(null)
        .size([diameter, diameter])
        .padding(1.5);

    var svg = d3.select(targetId).append("svg")
        .attr("width", diameter)
        .attr("height", diameter)

    var wordList = []; //each word one entry and contains the total count [ {cnt:30,title_list:[3,5,9],
    var wordCount = [];
    var wordMap = {};
    var wordIdList = [];
    var minVal = 10000;
    var maxVal = -100;
    var wordId = 0;
    var wordStr = "";

    for (var i = 0; i < plotData.length; i++) {
        wordStr = plotData[i];
        try {
            if (typeof(wordStr) != "undefined" && wordStr.length > 0) {
                wordStr = wordStr.toLowerCase();
                if (typeof(wordMap[wordStr]) == "undefined") {
                    wordList.push(wordStr);
                    wordCount.push(1);
                    wordMap[wordStr] = wordId;
                    wordIdList.push(wordId);
                    wordId++;
                } else {
                    wordCount[wordMap[wordStr]]++;
                }
            }   
        } catch (err) {
            alert("Error encountered parsing supplied words.")
        }
    }

    wordIdList.sort(function(x, y) { 
        return -wordCount[x] + wordCount[y] 
    });

    for (var wi = 0; wi < wordList.length; wi++) {
        if (minVal > wordCount[wi] ) minVal = wordCount[wi];
        if (maxVal < wordCount[wi] ) maxVal = wordCount[wi];
    }  

    var data = [
        wordList,
        wordCount
    ];

    var dobj=[];
    for (var di = 0; di < data[0].length; di++) {
        dobj.push({"key": di, "value": data[1][di]});
    }

    display_pack({children: dobj});

    function display_pack(root) {
        var node = svg.selectAll(".node")
            .data(bubble.nodes(root)
                .filter(function(d) { return !d.children; }))
            .enter().append("g")
            .attr("class", "node")
            .attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; })
            .style("fill", function(d) { return color(data[0][d.key]); })
            .on("mouseover", function(d,i) {
                d3.select(this).style("fill", "gold"); 
                showToolTip(" "+data[0][i]+"<br>"+data[1][i]+" ",d3.event.pageX+10, d3.event.pageY+10,true);
            })
            .on("mouseout", function() {
                d3.select(this).style("fill", function(d) { return color(data[0][d.key]); });
                showToolTip(" ",0,0,false);
            });

        node.append("circle")
            .attr("r", function(d) { return d.r; });

        node.append("text")
            .attr("dy", ".3em")
            .style("font", "10px sans-serif")
            .style("text-anchor", "middle")
            .style("fill","black")
            .text(function(d) { return data[0][d.key].substring(0, d.r / 3); });
    }

    function showToolTip(pMessage,pX,pY,pShow) {
        if (typeof(tooltipDivID)=="undefined") {
            tooltipDivID =$('<div id="messageToolTipDiv" style="position:absolute;display:block;z-index:10000;border:2px solid black;background-color:rgba(0,0,0,0.8);margin:auto;padding:3px 5px 3px 5px;color:white;font-size:12px;font-family:arial;border-radius: 5px;vertical-align: middle;text-align: center;min-width:50px;overflow:auto;"></div>');

            $('body').append(tooltipDivID);
        }

        if (!pShow) { tooltipDivID.hide(); return;}
            tooltipDivID.html(pMessage);
            tooltipDivID.css({top:pY,left:pX});
            tooltipDivID.show();
        }
}
