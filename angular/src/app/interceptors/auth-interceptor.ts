import { Injectable } from '@angular/core';
import { HttpRequest, HttpHandler, HttpEvent, HttpInterceptor } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {

    /**
     * Here we can stablish the logic for the differnet roles
     */
    intercept(req: HttpRequest<any>,
        next: HttpHandler): Observable<HttpEvent<any>> {

        // we get the jwt token from the localstorage
        const idToken = localStorage.getItem("token");

        // if we have the token we will try to put it in the headers
        if (idToken) {
            console.log("entra");
            // We clone the request and we will add an Authorization header adding the token 
            const cloned = req.clone({
                headers: req.headers.set("Authorization", idToken)
            });

            // we continue the pipeline
            return next.handle(cloned);
        }
        else {
            // If we don't have we will send the original request
            return next.handle(req);
        }
    }
}