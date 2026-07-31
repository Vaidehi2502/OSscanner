import "@testing-library/jest-dom";

// jsdom doesn't implement scrollTo; App.js calls it after loading a scan.
window.scrollTo = jest.fn();
