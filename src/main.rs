use authorization::auth::{Role, UserStore};

fn main() {
    let mut store = UserStore::new();

    store
        .add_user("admin", "password", Role::Admin)
        .expect("failed to add admin");
    store
        .add_user("moderator", "password", Role::Moderator)
        .expect("failed to add moderator");
    store
        .add_user("user", "password", Role::User)
        .expect("failed to add user");

    println!("Trying to authenticate `admin` with correct password…");
    match store.authenticate("admin", "password") {
        Ok(user) => println!("Authenticated as {} ({:?})", user.username(), user.role()),
        Err(err) => eprintln!("Authentication failed: {err}"),
    }

    println!("Checking if `moderator` can perform an Admin action…");
    match store.authorize("moderator", Role::Admin) {
        Ok(()) => println!("Moderator is allowed to act as Admin"),
        Err(err) => eprintln!("Authorization failed: {err}"),
    }
}

