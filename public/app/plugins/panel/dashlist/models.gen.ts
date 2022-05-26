//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// This file was autogenerated by cuetsy. DO NOT EDIT!
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


export const modelVersion = Object.freeze([0, 0]);


export enum PanelLayout {
  List = 'list',
  Previews = 'previews',
}

export interface PanelOptions {
  folderId?: number;
  layout?: PanelLayout;
  maxItems: number;
  query: string;
  showHeadings: boolean;
  showRecentlyViewed: boolean;
  showSearch: boolean;
  showStarred: boolean;
  tags: string[];
}

export const defaultPanelOptions: Partial<PanelOptions> = {
  layout: PanelLayout.List,
  maxItems: 10,
  query: '',
  showHeadings: true,
  showRecentlyViewed: false,
  showSearch: false,
  showStarred: true,
  tags: [],
};
