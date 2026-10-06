import Sidebar from "./Sidebar";

function PageLayout({
  title,
  subtitle,
  children,
}) {
  return (
    <div className="app">

      <Sidebar />

      <main className="main-content">

        <div className="page-layout">

          <div className="page-header">

            <div>
              <h1>{title}</h1>

              {subtitle && (
                <p>{subtitle}</p>
              )}
            </div>

            <div className="page-live">
              <span></span>
              LIVE
            </div>

          </div>

          <div className="page-body">
            {children}
          </div>

        </div>

      </main>

    </div>
  );
}

export default PageLayout;
