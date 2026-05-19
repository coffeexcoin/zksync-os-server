use futures::FutureExt;
use futures::future::BoxFuture;
use std::future::Future;
use std::pin::Pin;

pub type BoxZkExEx = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'static>>;

/// A typed launcher for an in-process ZKsync ExEx.
pub trait LaunchZkExEx<Ctx>: Send + 'static {
    type ExEx: Future<Output = anyhow::Result<()>> + Send + 'static;
    type LaunchFuture: Future<Output = anyhow::Result<Self::ExEx>> + Send;

    fn launch(self, ctx: Ctx) -> Self::LaunchFuture;
}

impl<Ctx, F, Fut, ExEx> LaunchZkExEx<Ctx> for F
where
    F: FnOnce(Ctx) -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<ExEx>> + Send,
    ExEx: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    type ExEx = ExEx;
    type LaunchFuture = Fut;

    fn launch(self, ctx: Ctx) -> Self::LaunchFuture {
        self(ctx)
    }
}

/// Object-safe launcher used by node integration code.
pub trait BoxedLaunchZkExEx<Ctx>: Send + 'static {
    fn launch(self: Box<Self>, ctx: Ctx) -> BoxFuture<'static, anyhow::Result<BoxZkExEx>>;
}

impl<Ctx, L> BoxedLaunchZkExEx<Ctx> for L
where
    Ctx: Send + 'static,
    L: LaunchZkExEx<Ctx>,
{
    fn launch(self: Box<Self>, ctx: Ctx) -> BoxFuture<'static, anyhow::Result<BoxZkExEx>> {
        async move {
            let exex = (*self).launch(ctx).await?;
            Ok(Box::pin(exex) as BoxZkExEx)
        }
        .boxed()
    }
}
