/*
 * Copyright (C) 2013, 2015 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

WI.ResourceSidebarPanel = class ResourceSidebarPanel extends WI.NavigationSidebarPanel
{
    constructor(contentBrowser)
    {
        super("resource", WI.UIString("Resources"), true);

        this.contentBrowser = contentBrowser;

        this._navigationBar = new WI.NavigationBar;
        this.insertSubviewBefore(this._navigationBar, this._contentView);

        this._targetTreeElementMap = new Map;

        var scopeItemPrefix = "resource-sidebar-";
        var scopeBarItems = [];

        scopeBarItems.push(new WI.ScopeBarItem(scopeItemPrefix + "type-all", WI.UIString("All Resources"), true));

        for (var key in WI.Resource.Type) {
            var value = WI.Resource.Type[key];
            var scopeBarItem = new WI.ScopeBarItem(scopeItemPrefix + value, WI.Resource.displayNameForType(value, true));
            scopeBarItem[WI.ResourceSidebarPanel.ResourceTypeSymbol] = value;
            scopeBarItems.push(scopeBarItem);
        }

        if (window.CanvasAgent && WI.settings.experimentalShowCanvasContextsInResources.value) {
            let canvasesScopeBarItem = new WI.ScopeBarItem(scopeItemPrefix + WI.Canvas.ResourceSidebarType, WI.UIString("Canvases"));
            canvasesScopeBarItem[WI.ResourceSidebarPanel.ResourceTypeSymbol] = WI.Canvas.ResourceSidebarType;
            scopeBarItems.insertAtIndex(canvasesScopeBarItem, scopeBarItems.length - 1);
        }

        this._scopeBar = new WI.ScopeBar("resource-sidebar-scope-bar", scopeBarItems, scopeBarItems[0], true);
        this._scopeBar.addEventListener(WI.ScopeBar.Event.SelectionChanged, this._scopeBarSelectionDidChange, this);

        this._navigationBar.addNavigationItem(this._scopeBar);

        WI.Frame.addEventListener(WI.Frame.Event.MainResourceDidChange, this._mainResourceDidChange, this);

        WI.frameResourceManager.addEventListener(WI.FrameResourceManager.Event.MainFrameDidChange, this._mainFrameDidChange, this);

        WI.debuggerManager.addEventListener(WI.DebuggerManager.Event.ScriptAdded, this._scriptWasAdded, this);
        WI.debuggerManager.addEventListener(WI.DebuggerManager.Event.ScriptRemoved, this._scriptWasRemoved, this);
        WI.debuggerManager.addEventListener(WI.DebuggerManager.Event.ScriptsCleared, this._scriptsCleared, this);

        WI.cssStyleManager.addEventListener(WI.CSSStyleManager.Event.StyleSheetAdded, this._styleSheetAdded, this);

        WI.targetManager.addEventListener(WI.TargetManager.Event.TargetRemoved, this._targetRemoved, this);

        WI.notifications.addEventListener(WI.Notification.ExtraDomainsActivated, this._extraDomainsActivated, this);

        this.contentTreeOutline.addEventListener(WI.TreeOutline.Event.SelectionDidChange, this._treeSelectionDidChange, this);
        this.contentTreeOutline.includeSourceMapResourceChildren = true;

        if (WI.sharedApp.debuggableType === WI.DebuggableType.JavaScript) {
            this.contentTreeOutline.disclosureButtons = false;
            WI.SourceCode.addEventListener(WI.SourceCode.Event.SourceMapAdded, () => { this.contentTreeOutline.disclosureButtons = true; }, this);
        }
    }

    // Public

    get minimumWidth()
    {
        return this._navigationBar.minimumWidth;
    }

    closed()
    {
        super.closed();

        WI.Frame.removeEventListener(null, null, this);
        WI.frameResourceManager.removeEventListener(null, null, this);
        WI.debuggerManager.removeEventListener(null, null, this);
        WI.notifications.removeEventListener(null, null, this);
    }

    showDefaultContentView()
    {
        if (WI.frameResourceManager.mainFrame) {
            this.contentBrowser.showContentViewForRepresentedObject(WI.frameResourceManager.mainFrame);
            return;
        }

        var firstTreeElement = this.contentTreeOutline.children[0];
        if (firstTreeElement)
            this.showDefaultContentViewForTreeElement(firstTreeElement);
    }

    treeElementForRepresentedObject(representedObject)
    {
        // A custom implementation is needed for this since the frames are populated lazily.

        if (!this._mainFrameTreeElement && (representedObject instanceof WI.Resource || representedObject instanceof WI.Frame || representedObject instanceof WI.Collection)) {
            // All resources are under the main frame, so we need to return early if we don't have the main frame yet.
            return null;
        }

        // The Frame is used as the representedObject instead of the main resource in our tree.
        if (representedObject instanceof WI.Resource && representedObject.parentFrame && representedObject.parentFrame.mainResource === representedObject)
            representedObject = representedObject.parentFrame;

        function isAncestor(ancestor, resourceOrFrame)
        {
            // SourceMapResources are descendants of another SourceCode object.
            if (resourceOrFrame instanceof WI.SourceMapResource) {
                if (resourceOrFrame.sourceMap.originalSourceCode === ancestor)
                    return true;

                // Not a direct ancestor, so check the ancestors of the parent SourceCode object.
                resourceOrFrame = resourceOrFrame.sourceMap.originalSourceCode;
            }

            var currentFrame = resourceOrFrame.parentFrame;
            while (currentFrame) {
                if (currentFrame === ancestor)
                    return true;
                currentFrame = currentFrame.parentFrame;
            }

            return false;
        }

        function getParent(resourceOrFrame)
        {
            // SourceMapResources are descendants of another SourceCode object.
            if (resourceOrFrame instanceof WI.SourceMapResource)
                return resourceOrFrame.sourceMap.originalSourceCode;
            return resourceOrFrame.parentFrame;
        }

        var treeElement = this.contentTreeOutline.findTreeElement(representedObject, isAncestor, getParent);
        if (treeElement)
            return treeElement;

        // Only special case Script objects.
        if (!(representedObject instanceof WI.Script)) {
            console.error("Didn't find a TreeElement for representedObject", representedObject);
            return null;
        }

        // If the Script has a URL we should have found it earlier.
        if (representedObject.url) {
            console.error("Didn't find a ScriptTreeElement for a Script with a URL.");
            return null;
        }

        // Since the Script does not have a URL we consider it an 'anonymous' script. These scripts happen from calls to
        // window.eval() or browser features like Auto Fill and Reader. They are not normally added to the sidebar, but since
        // we have a ScriptContentView asking for the tree element we will make a ScriptTreeElement on demand and add it.

        if (!this._anonymousScriptsFolderTreeElement) {
            let collection = new WI.Collection(WI.Collection.TypeVerifier.Script);
            this._anonymousScriptsFolderTreeElement = new WI.FolderTreeElement(WI.UIString("Anonymous Scripts"), collection);
        }

        if (!this._anonymousScriptsFolderTreeElement.parent) {
            var index = insertionIndexForObjectInListSortedByFunction(this._anonymousScriptsFolderTreeElement, this.contentTreeOutline.children, this._compareTreeElements);
            this.contentTreeOutline.insertChild(this._anonymousScriptsFolderTreeElement, index);
        }

        this._anonymousScriptsFolderTreeElement.representedObject.add(representedObject);

        var scriptTreeElement = new WI.ScriptTreeElement(representedObject);
        this._anonymousScriptsFolderTreeElement.appendChild(scriptTreeElement);

        return scriptTreeElement;
    }

    // Protected

    initialLayout()
    {
        super.initialLayout();

        if (WI.frameResourceManager.mainFrame)
            this._mainFrameMainResourceDidChange(WI.frameResourceManager.mainFrame);

        for (let script of WI.debuggerManager.knownNonResourceScripts) {
            this._addScript(script);

            if (script.sourceMaps.length && WI.sharedApp.debuggableType === WI.DebuggableType.JavaScript)
                this.contentTreeOutline.disclosureButtons = true;
        }
    }

    hasCustomFilters()
    {
        console.assert(this._scopeBar.selectedItems.length === 1);
        var selectedScopeBarItem = this._scopeBar.selectedItems[0];
        return selectedScopeBarItem && !selectedScopeBarItem.exclusive;
    }

    matchTreeElementAgainstCustomFilters(treeElement, flags)
    {
        console.assert(this._scopeBar.selectedItems.length === 1);
        var selectedScopeBarItem = this._scopeBar.selectedItems[0];

        // Show everything if there is no selection or "All Resources" is selected (the exclusive item).
        if (!selectedScopeBarItem || selectedScopeBarItem.exclusive)
            return true;

        // Folders are hidden on the first pass, but visible childen under the folder will force the folder visible again.
        if (treeElement instanceof WI.FolderTreeElement)
            return false;

        function match()
        {
            if (treeElement instanceof WI.FrameTreeElement)
                return selectedScopeBarItem[WI.ResourceSidebarPanel.ResourceTypeSymbol] === WI.Resource.Type.Document;

            if (treeElement instanceof WI.ScriptTreeElement)
                return selectedScopeBarItem[WI.ResourceSidebarPanel.ResourceTypeSymbol] === WI.Resource.Type.Script;

            if (treeElement instanceof WI.CanvasTreeElement || treeElement instanceof WI.ShaderProgramTreeElement)
                return selectedScopeBarItem[WI.ResourceSidebarPanel.ResourceTypeSymbol] === WI.Canvas.ResourceSidebarType;

            if (treeElement instanceof WI.CSSStyleSheetTreeElement)
                return selectedScopeBarItem[WI.ResourceSidebarPanel.ResourceTypeSymbol] === WI.Resource.Type.Stylesheet;

            console.assert(treeElement instanceof WI.ResourceTreeElement, "Unknown treeElement", treeElement);
            if (!(treeElement instanceof WI.ResourceTreeElement))
                return false;

            return treeElement.resource.type === selectedScopeBarItem[WI.ResourceSidebarPanel.ResourceTypeSymbol];
        }

        var matched = match();
        if (matched)
            flags.expandTreeElement = true;
        return matched;
    }

    // Private

    _mainResourceDidChange(event)
    {
        if (!event.target.isMainFrame())
            return;

        this._mainFrameMainResourceDidChange(event.target);
    }

    _mainFrameDidChange(event)
    {
        this._mainFrameMainResourceDidChange(WI.frameResourceManager.mainFrame);
    }

    _mainFrameMainResourceDidChange(mainFrame)
    {
        this.contentBrowser.contentViewContainer.closeAllContentViews();

        if (this._mainFrameTreeElement) {
            this.contentTreeOutline.removeChild(this._mainFrameTreeElement);
            this._mainFrameTreeElement = null;
        }

        if (!mainFrame)
            return;

        this._mainFrameTreeElement = new WI.FrameTreeElement(mainFrame);
        this.contentTreeOutline.insertChild(this._mainFrameTreeElement, 0);

        function delayedWork()
        {
            if (!this.contentTreeOutline.selectedTreeElement) {
                var currentContentView = this.contentBrowser.currentContentView;
                var treeElement = currentContentView ? this.treeElementForRepresentedObject(currentContentView.representedObject) : null;
                if (!treeElement)
                    treeElement = this._mainFrameTreeElement;
                this.showDefaultContentViewForTreeElement(treeElement);
            }
        }

        // Cookie restoration will attempt to re-select the resource we were showing.
        // Give it time to do that before selecting the main frame resource.
        setTimeout(delayedWork.bind(this));
    }

    _scriptWasAdded(event)
    {
        this._addScript(event.data.script);
    }

    _addScript(script)
    {
        // We don't add scripts without URLs here. Those scripts can quickly clutter the interface and
        // are usually more transient. They will get added if/when they need to be shown in a content view.
        if (!script.url && !script.sourceURL)
            return;

        // Worker script.
        if (script.target !== WI.mainTarget) {
            if (script.isMainResource())
                this._addTargetWithMainResource(script.target);
            return;
        }

        // If the script URL matches a resource we can assume it is part of that resource and does not need added.
        if (script.resource || script.dynamicallyAddedScriptElement)
            return;

        let insertIntoTopLevel = false;
        let parentFolderTreeElement = null;

        if (script.injected) {
            if (!this._extensionScriptsFolderTreeElement) {
                let collection = new WI.Collection(WI.Collection.TypeVerifier.Script);
                this._extensionScriptsFolderTreeElement = new WI.FolderTreeElement(WI.UIString("Extension Scripts"), collection);
            }

            parentFolderTreeElement = this._extensionScriptsFolderTreeElement;
        } else {
            if (WI.sharedApp.debuggableType === WI.DebuggableType.JavaScript && !WI.sharedApp.hasExtraDomains)
                insertIntoTopLevel = true;
            else {
                if (!this._extraScriptsFolderTreeElement) {
                    let collection = new WI.Collection(WI.Collection.TypeVerifier.Script);
                    this._extraScriptsFolderTreeElement = new WI.FolderTreeElement(WI.UIString("Extra Scripts"), collection);
                }

                parentFolderTreeElement = this._extraScriptsFolderTreeElement;
            }
        }

        if (parentFolderTreeElement)
            parentFolderTreeElement.representedObject.add(script);

        var scriptTreeElement = new WI.ScriptTreeElement(script);

        if (insertIntoTopLevel) {
            var index = insertionIndexForObjectInListSortedByFunction(scriptTreeElement, this.contentTreeOutline.children, this._compareTreeElements);
            this.contentTreeOutline.insertChild(scriptTreeElement, index);
        } else {
            if (!parentFolderTreeElement.parent) {
                var index = insertionIndexForObjectInListSortedByFunction(parentFolderTreeElement, this.contentTreeOutline.children, this._compareTreeElements);
                this.contentTreeOutline.insertChild(parentFolderTreeElement, index);
            }

            parentFolderTreeElement.appendChild(scriptTreeElement);
        }
    }

    _scriptWasRemoved(event)
    {
        let script = event.data.script;
        let scriptTreeElement = this.contentTreeOutline.getCachedTreeElement(script);
        if (!scriptTreeElement)
            return;

        let parentTreeElement = scriptTreeElement.parent;
        parentTreeElement.removeChild(scriptTreeElement);

        if (parentTreeElement instanceof WI.FolderTreeElement) {
            parentTreeElement.representedObject.remove(script);

            if (!parentTreeElement.children.length)
                parentTreeElement.parent.removeChild(parentTreeElement);
        }
    }

    _scriptsCleared(event)
    {
        const suppressOnDeselect = true;
        const suppressSelectSibling = true;

        if (this._extensionScriptsFolderTreeElement) {
            if (this._extensionScriptsFolderTreeElement.parent)
                this._extensionScriptsFolderTreeElement.parent.removeChild(this._extensionScriptsFolderTreeElement, suppressOnDeselect, suppressSelectSibling);

            this._extensionScriptsFolderTreeElement.representedObject.clear();
            this._extensionScriptsFolderTreeElement = null;
        }

        if (this._extraScriptsFolderTreeElement) {
            if (this._extraScriptsFolderTreeElement.parent)
                this._extraScriptsFolderTreeElement.parent.removeChild(this._extraScriptsFolderTreeElement, suppressOnDeselect, suppressSelectSibling);

            this._extraScriptsFolderTreeElement.representedObject.clear();
            this._extraScriptsFolderTreeElement = null;
        }

        if (this._anonymousScriptsFolderTreeElement) {
            if (this._anonymousScriptsFolderTreeElement.parent)
                this._anonymousScriptsFolderTreeElement.parent.removeChild(this._anonymousScriptsFolderTreeElement, suppressOnDeselect, suppressSelectSibling);

            this._anonymousScriptsFolderTreeElement.representedObject.clear();
            this._anonymousScriptsFolderTreeElement = null;
        }

        if (this._targetTreeElementMap.size) {
            for (let treeElement of this._targetTreeElementMap)
                treeElement.parent.removeChild(treeElement, suppressOnDeselect, suppressSelectSibling);
            this._targetTreeElementMap.clear();
        }
    }

    _styleSheetAdded(event)
    {
        let styleSheet = event.data.styleSheet;
        if (!styleSheet.isInspectorStyleSheet())
            return;

        let frameTreeElement = this.treeElementForRepresentedObject(styleSheet.parentFrame);
        if (!frameTreeElement)
            return;

        frameTreeElement.addRepresentedObjectToNewChildQueue(styleSheet);
    }

    _addTargetWithMainResource(target)
    {
        console.assert(target.type === WI.Target.Type.Worker);

        let targetTreeElement = new WI.WorkerTreeElement(target);
        this._targetTreeElementMap.set(target, targetTreeElement);

        let index = insertionIndexForObjectInListSortedByFunction(targetTreeElement, this.contentTreeOutline.children, this._compareTreeElements);
        this.contentTreeOutline.insertChild(targetTreeElement, index);
    }

    _targetRemoved(event)
    {
        let removedTarget = event.data.target;

        let targetTreeElement = this._targetTreeElementMap.take(removedTarget);
        if (targetTreeElement)
            targetTreeElement.parent.removeChild(targetTreeElement);
    }

    _treeSelectionDidChange(event)
    {
        if (!this.visible)
            return;

        let treeElement = event.data.selectedElement;
        if (!treeElement)
            return;

        if (treeElement instanceof WI.FolderTreeElement
            || treeElement instanceof WI.ResourceTreeElement
            || treeElement instanceof WI.ScriptTreeElement
            || treeElement instanceof WI.CSSStyleSheetTreeElement
            || treeElement instanceof WI.CanvasTreeElement
            || treeElement instanceof WI.ShaderProgramTreeElement) {
            const cookie = null;
            const options = {
                ignoreNetworkTab: true,
                ignoreSearchTab: true,
            };
            WI.showRepresentedObject(treeElement.representedObject, cookie, options);
            return;
        }

        console.error("Unknown tree element", treeElement);
    }

    _compareTreeElements(a, b)
    {
        // Always sort the main frame element first.
        if (a instanceof WI.FrameTreeElement)
            return -1;
        if (b instanceof WI.FrameTreeElement)
            return 1;

        console.assert(a.mainTitle);
        console.assert(b.mainTitle);

        return (a.mainTitle || "").extendedLocaleCompare(b.mainTitle || "");
    }

    _extraDomainsActivated()
    {
        if (WI.sharedApp.debuggableType === WI.DebuggableType.JavaScript)
            this.contentTreeOutline.disclosureButtons = true;
    }

    _scopeBarSelectionDidChange(event)
    {
        this.updateFilter();
    }
};

WI.ResourceSidebarPanel.ResourceTypeSymbol = Symbol("resource-type");
