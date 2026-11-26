import { Component } from "react";

// Catches render errors so one bad payload can never blank the whole app. Shows the error so it can be reported.
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // eslint-disable-next-line no-console
    console.error("UI error:", error, info?.componentStack);
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    if (this.props.inline) {
      return <div className="alert alert-error" role="alert"><strong>This message could not be displayed.</strong>
        <div className="small">{String(error?.message || error)}</div></div>;
    }
    return (
      <div className="alert alert-error" role="alert" style={{ margin: 24 }}>
        <strong>Something went wrong while displaying this page.</strong>
        <div className="small">{String(error?.message || error)}</div>
        <button className="btn" onClick={() => this.setState({ error: null })}>Try again</button>{" "}
        <button className="btn" onClick={() => window.location.assign("/")}>Go to dashboard</button>
      </div>
    );
  }
}
