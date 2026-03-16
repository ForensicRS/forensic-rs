pub mod fs;

pub type UserEnvVars = std::collections::BTreeMap<String, String>;
pub type UsersEnvVars = std::collections::BTreeMap<String, UserEnvVars>;

pub fn interpolate_env_vars(pth : &str, env_vars : &UserEnvVars, ret : &mut String) -> Option<()>{
    if let Some(stripped) = pth.strip_prefix('%') {
        let pos = stripped.as_bytes().iter().position(|&v| v == b'%')?;
        let env_var = &stripped[..pos];
        let rest = if pos + 1 > stripped.len() { "" } else {&stripped[pos + 1..]};
        let to_replace_with = env_vars.get(env_var)?;
        interpolate_env_vars(to_replace_with, env_vars, ret)?;
        ret.push_str(rest);
    }else {
        ret.push_str(pth);
    }
    Some(())
}