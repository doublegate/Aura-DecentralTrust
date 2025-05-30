use aura_common::*;
use aura_crypto::*;
use aura_wallet_core::*;
use std::collections::HashMap;

fn main() -> Result<()> {
    println!("=== Aura Basic Usage Example ===\n");
    
    // 1. Create an issuer (e.g., a university)
    println!("1. Creating issuer identity...");
    let mut issuer_wallet = AuraWallet::new();
    issuer_wallet.initialize("issuer_password")?;
    
    let (issuer_did, issuer_did_doc, _) = issuer_wallet.create_did()?;
    println!("   Issuer DID: {}", issuer_did);
    
    // 2. Create a holder (e.g., a student)
    println!("\n2. Creating holder identity...");
    let mut holder_wallet = AuraWallet::new();
    holder_wallet.initialize("holder_password")?;
    
    let (holder_did, holder_did_doc, _) = holder_wallet.create_did()?;
    println!("   Holder DID: {}", holder_did);
    
    // 3. Issue a credential
    println!("\n3. Issuing credential...");
    let mut claims = HashMap::new();
    claims.insert("name".to_string(), serde_json::json!("Alice Johnson"));
    claims.insert("degree".to_string(), serde_json::json!("Computer Science"));
    claims.insert("graduationDate".to_string(), serde_json::json!("2023-06-15"));
    claims.insert("gpa".to_string(), serde_json::json!(3.8));
    
    let credential = VerifiableCredential::new(
        issuer_did.clone(),
        holder_did.clone(),
        vec!["UniversityDegreeCredential".to_string()],
        claims,
    );
    
    // Sign the credential
    let issuer_key = issuer_wallet.get_did_public_key(&issuer_did)?;
    
    // Store credential in holder's wallet
    let credential_id = holder_wallet.store_credential(
        credential.clone(),
        vec!["education".to_string(), "degree".to_string()],
    )?;
    println!("   Credential ID: {}", credential_id);
    
    // 4. Create a presentation
    println!("\n4. Creating verifiable presentation...");
    let presentation = holder_wallet.create_presentation(
        &holder_did,
        vec![credential_id.clone()],
        Some("challenge-123".to_string()),
        Some("example.com".to_string()),
    )?;
    println!("   Presentation created with {} credential(s)", presentation.verifiable_credential.len());
    
    // 5. Verify the presentation
    println!("\n5. Verifying presentation...");
    let holder_public_key = holder_wallet.get_did_public_key(&holder_did)?;
    
    let is_valid = holder_wallet.verify_presentation(
        &presentation,
        &holder_public_key,
        Some("challenge-123"),
        Some("example.com"),
    )?;
    
    println!("   Presentation valid: {}", is_valid);
    
    // 6. Create selective disclosure presentation
    println!("\n6. Creating selective disclosure presentation...");
    let selective_presentation = holder_wallet.create_selective_presentation(
        &holder_did,
        credential_id,
        vec!["name".to_string(), "degree".to_string()], // Only disclose name and degree
        None,
        None,
    )?;
    
    println!("   Selective presentation created");
    println!("   Disclosed claims:");
    for (key, value) in &selective_presentation.verifiable_credential[0].credential_subject.claims {
        println!("     - {}: {}", key, value);
    }
    
    // 7. List credentials in wallet
    println!("\n7. Listing holder's credentials...");
    let credentials = holder_wallet.list_credentials();
    for stored_cred in credentials {
        println!("   - ID: {}", stored_cred.id);
        println!("     Type: {:?}", stored_cred.credential.credential_type);
        println!("     Tags: {:?}", stored_cred.tags);
    }
    
    println!("\n=== Example completed successfully! ===");
    
    Ok(())
}