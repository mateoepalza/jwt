import { Injectable } from '@angular/core';
import * as moment from "moment";

@Injectable()
export class AuthService {

    constructor() {}
          
    setLocalStorage(responseObj) {
        console.log(responseObj);
        // This gives the time when the jwt expires
        const expires =  moment().add(responseObj.expiresIn);
        
        // We save the token and we save when it expires
        localStorage.setItem('token', responseObj.token);
        localStorage.setItem('expires', JSON.stringify(expires.valueOf()));
    }          

    logout() {
        // We delete the properties from the localstorage
        localStorage.removeItem('token');
        localStorage.removeItem('expires');
    }

    isLoggedIn() {
        // This checks if the actual time is before the expiration time
            // if it is returns true otherwise return false
        return moment().isBefore(this.getExpiration());
    }

    isLoggedOut() {
        // checks if we are logged out
        return !this.isLoggedIn();
    }

    getExpiration() {
        // we get the property expires
        const expiration = localStorage.getItem('expires');
        // we parse the object 
        const expiresAt = JSON.parse(expiration);
        // calculate using the moment library, it calculate the exact time when the jwt expires
        return moment(expiresAt);

    }    
}