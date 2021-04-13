// during development
#![allow(dead_code)]

mod basic_components;
mod dashboard;
mod events_listener;
mod logging_backend;
mod session;
mod translation;

use alvr_common::{logging, prelude::*};
use dashboard::Dashboard;
use std::{
    cell::RefCell,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
};
use translation::TransProvider;
use wasm_bindgen::prelude::*;
use yew::{html, Callback};
use yew_functional::{function_component, use_effect_with_deps, use_state};

static ID_COUNTER: AtomicUsize = AtomicUsize::new(1);

pub fn get_id() -> String {
    format!("alvr{}", ID_COUNTER.fetch_add(1, Ordering::Relaxed))
}

#[function_component(Root)]
fn root() -> Html {
    let (maybe_session, set_session) = use_state(|| None);

    let events_callback_ref = Rc::new(RefCell::new(Callback::default()));

    // run only once
    use_effect_with_deps(
        {
            let events_callback_ref = Rc::clone(&events_callback_ref);
            move |_| {
                wasm_bindgen_futures::spawn_local(async move {
                    logging::show_err_async(async {
                        let initial_session = session::fetch_session().await?;

                        translation::change_language(
                            &initial_session.session_settings.extra.language,
                        )
                        .await;

                        set_session(Some(initial_session));

                        events_listener::events_listener(|event| async {
                            match event {
                                Event::SessionUpdated { .. } => {
                                    let session = session::fetch_session().await?;

                                    translation::change_language(
                                        &session.session_settings.extra.language,
                                    )
                                    .await;

                                    set_session(Some(session));
                                }
                                event => events_callback_ref.borrow().emit(event),
                            }

                            Ok(())
                        })
                        .await
                    })
                    .await;
                });

                || ()
            }
        },
        (),
    );

    if let Some(session) = &*maybe_session {
        html! {
            <TransProvider>
                <Dashboard events_callback_ref=events_callback_ref session=session.clone() />
            </TransProvider>
        }
    } else {
        html!(<h1 class="position-absolute top-50 start-50 translate-middle">{"Loading..."}</h1>)
    }
}

#[wasm_bindgen(start)]
pub fn main() {
    logging_backend::init();

    yew::start_app::<Root>();
}
