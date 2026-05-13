<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=social.displayInfo; section>
<#if section = "title">
    ${msg("loginTitle",(realm.displayName!''))}
    <#elseif section = "header">
    <#elseif section = "form">
    <#if realm.password>
    <div class="custom-wrapper">
        <div class="custom-grid">
            <div class="ui raised shadow container segment fullpage-background-image left-box">
                <div class="ui column height-fix" style="padding:0">

                    <div class="logo" style="width: 320px; max-width:100%">
                        <img alt="Logo" src="${url.resourcesPath}/img/dopt_logo.png" style="width: inherit;">
                    </div>
                    <div class="img-container" style="width: 320px; max-width:100%">
                        <div class="slideshow-container">

                            <div class="mySlides fade">
                                <img alt="Slides" src="${url.resourcesPath}/img/Hexagon.png">
                            </div>

                            <#--  <div class="mySlides fade">
                                <img alt="Slides" src="${url.resourcesPath}/img/card1.png">
                            </div>

                            <div class="mySlides fade">
                                <img alt="Slides" src="${url.resourcesPath}/img/card2.png">
                            </div>  -->
                            <div class="mySlides fade">
                                <img alt="Slides" src="${url.resourcesPath}/img/card3.png">
                            </div>

                        </div>
                    </div>
                    <div class="dots-menu">
                        <span class="dot">*</span>
                        <span class="dot">*</span>
                        <#--  <span class="dot">*</span>  -->
                    </div>
                </div>
                
            </div>
            <div class="ui raised shadow container segment fullpage-background-image login-section">
                <div class="ui one column grid stackable">
                    <#--  <div class="ui column tablet only computer only"></div>  -->
                    <div class="ui column height-fix">
                        <div class="max-container">
                            <div class="ui header mb-40 centered">
                                <img onerror="" alt="Error">
                                <#--  <div class="signInHead mt-27">${msg("doSignIn")}</div>  -->
                            </div>

                            <div class="formMsg  textCenter">
                                <#if message?has_content>
                                <div class="ui text mb-30 ${message.type}">
                                    ${message.summary}
                                </div>
                                </#if>
                                <div id="success-msg" class="ui text success hide">suceess</div>
                                <div id="error-msg" class="ui text error hide">error</div>
                            </div>
                            <div class="field ${properties.kcFormGroupClass!} type-container mw-100">
                                <div>
                                    <input type="radio" onclick="javascript:passwordOrOtp();" name="usePasswordOrOTP" id="usePasswordRB" checked=true>&nbsp;
                                    <label id="usePasswordLabel" for="usePasswordRB" class="">
                                        Login with password
                                    </label>
                                </div>
                                <div>
                                    <input type="radio" onclick="javascript:passwordOrOtp();" name="usePasswordOrOTP" id="useOTPRB" class="">&nbsp;
                                    <label id="useOTPLabel" for="useOTPRB" class="">
                                        Login with OTP
                                    </label>
                                </div>
                            </div>
                            <div id="usePasswordDiv" class="mw-100" >
                                <form id="kc-form-login" onsubmit="login.disabled = true; return true;" class="ui form" method="POST" action="${url.loginAction}">
				                    <input type="hidden" name="page_type" value="login_with_pass" />
                                    <div class="field">
                                        <label id="usernameLabel" for="username" class="">
                                            <#if !realm.loginWithEmailAllowed>${msg("username")}
                                            <#elseif !realm.registrationEmailAsUsername>${msg("emailOrPhone")}
                                            <#else>${msg("email")}
                                            </#if>
                                        </label>
                                        <label id="usernameLabelPlaceholder" for="username" class="activeLabelColor hide">
                                            <#if !realm.loginWithEmailAllowed>${msg("username")}
                                            <#elseif !realm.registrationEmailAsUsername>${msg("placeholderForEmailOrPhone")}
                                            <#else>${msg("email")}
                                            </#if>
                                        </label>
                                        <#if usernameEditDisabled??>
                                        <#-- TODO: need to find alternative for prepopulating username -->
                                        <input class="mt-8" id="username" name="username" type="text" disabled />
                                        <#else>
                                        <input class="mt-8" id="username" name="username" onfocusin="inputBoxFocusIn(this)" onfocusout="inputBoxFocusOut(this)" type="text" autofocus autocomplete="off" />
                                        </#if>
                                    </div>
                                    <div class="field">
                                        <div>
                                            <label id="passwordLabel" for="password" class="">
                                                ${msg("password")}
                                            </label>
                                            <#if realm.resetPasswordAllowed>
                                                <a id="fgtKeycloakFlow" class="ui right floated forgetPasswordLink hide" tabindex="1" onclick="javascript:storeLocation(); javascript:makeDivUnclickable()" href="${url.loginResetCredentialsUrl}">${msg("doForgotPassword")}</a>
                                                <div id="fgtPortalFlow" class="ui right floated forgetPasswordLink hide" tabindex="1" onclick="javascript:forgetPassword('/recover/identify/account');javascript:makeDivUnclickable()">${msg("doForgotPassword")}</div>
                                            </#if>
                                            <label id="passwordLabelPlaceholder" for="password" class="activeLabelColor hide">
                                                ${msg("placeholderForPassword")}
                                            </label>
                                        </div>
                                        <input placeholder="${msg('passwordPlaceholder')}" class=" mt-8" id="password" onfocusin="inputBoxFocusIn(this)" onfocusout="inputBoxFocusOut(this)" name="password" type="password" autocomplete="off" />
                                        <span class="ui text error hide" id="inCorrectPasswordError">${msg("inCorrectPasswordError")}</span>
                                    </div>
                                    <div class="field">
                                    <#if recaptchaRequired??>
                                        <div class="form-group">
                                            <div class="${properties.kcInputWrapperClass!}">
                                                <div class="g-recaptcha" data-size="compact" data-sitekey="${recaptchaSiteKey}"></div>
                                            </div>
                                        </div>
                                    </#if>
                                    </div>
                                    <div class="field">
                                        <button id="login" class="ui fluid button">${msg("doLogIn")}</button>
                                    </div>
                                    <div class="field or-container">
                                        <div class="or-holder">
                                            <span class="or-divider"></span>
                                            <span class="or-text">or</span>
                                        </div>
                                    </div>
                                    <div class="field">
                                        <a id="loginp" href="/apis/public/v8/parichay/auth" class="ui fluid button">${msg("loginWithParichay")}</a>
                                    </div>
                                    <div id="kc-registration" class="field">
                                        <div class="ui content mt-40 signUpMsg">
                                            <span>${msg("noAccount")} <a class="signUpLink" href="${client.baseUrl}public/signup">${msg("registerHere")}</a></span>
                                        </div>
                                    </div>
                                    <div id="selfSingUp" class="hide">
                                        <p class="or my-16 textCenter">OR</p>
                                        <div class="field">
                                            <#if realm.password && social.providers??>
                                                <!--div id="kc-social-providers">
                                                    <#list social.providers as p>
                                                    <a href="${p.loginUrl}" id="zocial-${p.alias}" class="zocial ${p.providerId} ui fluid blue basic button textCenter">
                                                    <i class="icon signInWithGoogle"></i>${msg("doSignIn")} ${msg("doSignWithGoogle")}
                                                    </a>
                                                    </#list>
                                                </div-->
                                            </#if>
                                            <button type="button" id="stateButton" class="sb-btn sb-btn-normal sb-btn-success width-100 mb-16" onclick="navigate('state')">
                                                ${msg("doSignWithState")}
                                            </button>
                                            <button type="button" class="sb-btn sb-btn-normal sb-btn-outline-primary width-100 d-flex flex-ai-center flex-jc-center" onclick="navigate('google')">
                                            <img class="signInWithGoogle" src="${url.resourcesPath}/img/google.png">
                                            ${msg("doLogIn")} ${msg("doSignWithGoogle")}
                                            </button>
                                        </div>
                                        <#if realm.password && realm.registrationAllowed && !usernameEditDisabled??>
                                            <div id="kc-registration" class="field">
                                                <div class="ui content mt-40 signUpMsg">
                                                    ${msg("noAccount")} <span id="signup" tabindex="0" class="registerLink" onclick=navigate('self')>${msg("registerHere")}</span>
                                                    <span>${msg("noAccount")} <a class="signUpLink" href="${url.registrationUrl}">${msg("doRegister")}</a></span>
                                                </div>
                                            </div>
                                        </#if>
                                    </div>
                                </form>
                            </div>
                            <div id="useOTPDiv" class="mw-100" style="display:none">
                                <form id="kc-form-login" class="${properties.kcFormClass!} ui form" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post">
                                    <input type="hidden" name="page_type" value="login_page" />
                                    <#--  <div class="${properties.kcFormGroupClass!}">
                                        <div class="mdc-text-field mdc-text-field--with-leading-icon ${properties.kcLabelClass!} <#if usernameEditDisabled??>mdc-text-field--disabled</#if>">
                                            <i class="material-icons mdc-text-field__icon" role="button">phone</i>
                                            <input tabindex="0" required id="user.attributes.mobile_number" class="mdc-text-field__input ${properties.kcInputClass!}" name="user.attributes.mobile_number" type="text" autofocus autocomplete="off">
                                            <div class="mdc-line-ripple"></div>
                                            <label for="user.attributes.mobile_number" class="mdc-floating-label ${properties.kcLabelClass!}">
                                                Phone Number
                                            </label>
                                        </div>
                                    </div>  -->

                                    <div class="field">
                                        <div>
                                            <label id="phoneNumberLabel" for="emailOrPhone" class="">
                                                Email/Phone number
                                            </label>
                                            <label id="phoneNumberLabelPlaceholder" for="emailOrPhone" class="activeLabelColor hide">
                                                Email/Phone number
                                            </label>
                                        </div>
                                        <input tabindex="0" required id="emailOrPhone" placeholder="Email/Phone number (10 digit number)"
                                        class="mdc-text-field__input ${properties.kcInputClass!} mt-8" 
                                        name="emailOrPhone" type="text" autofocus autocomplete="off" onfocusin="inputBoxFocusIn(this)" onfocusout="inputBoxFocusOut(this)">
                                    </div>
                                    
                                    <div class="mdc-card__actions">
                                        <#--  <a href="${url.registrationUrl}" class="mdc-button mdc-card__action mdc-card__action--button">
                                            <i class="material-icons mdc-button__icon">arrow_back</i>Sign Up
                                        </a>  -->
                                        
                                        <div class="field">
                                            <button tabindex="0" name="login" id="kc-login" type="submit" class="ui fluid button">
                                                    Request OTP
                                            </button>
                                        </div>
                                        <div class="field or-container">
                                            <div class="or-holder">
                                                <span class="or-divider"></span>
                                                <span class="or-text">or</span>
                                            </div>
                                        </div>
                                        <div class="field">
                                            <a id="loginp" href="/apis/public/v8/parichay/auth" class="ui fluid button">${msg("loginWithParichay")}</a>
                                        </div>
                                        <div id="kc-registration" class="field">
                                            <div class="ui content mt-40 signUpMsg">
                                                <span>${msg("noAccount")} <a class="signUpLink" href="${client.baseUrl}public/signup">${msg("registerHere")}</a></span>
                                            </div>
                                        </div>
                                        <div id="selfSingUp" class="hide">
                                            <p class="or my-16 textCenter">OR</p>
                                            <div class="field">
                                                <#if realm.password && social.providers??>
                                                    <!--div id="kc-social-providers">
                                                        <#list social.providers as p>
                                                        <a href="${p.loginUrl}" id="zocial-${p.alias}" class="zocial ${p.providerId} ui fluid blue basic button textCenter">
                                                        <i class="icon signInWithGoogle"></i>${msg("doSignIn")} ${msg("doSignWithGoogle")}
                                                        </a>
                                                        </#list>
                                                    </div-->
                                                </#if>
                                                <button type="button" id="stateButton" class="sb-btn sb-btn-normal sb-btn-success width-100 mb-16" onclick="navigate('state')">
                                                    ${msg("doSignWithState")}
                                                </button>
                                                <button type="button" class="sb-btn sb-btn-normal sb-btn-outline-primary width-100 d-flex flex-ai-center flex-jc-center" onclick="navigate('google')">
                                                <img class="signInWithGoogle" src="${url.resourcesPath}/img/google.png">
                                                ${msg("doLogIn")} ${msg("doSignWithGoogle")}
                                                </button>
                                            </div>
                                            <#if realm.password && realm.registrationAllowed && !usernameEditDisabled??>
                                                <div id="kc-registration" class="field">
                                                    <div class="ui content mt-40 signUpMsg">
                                                        ${msg("noAccount")} <span id="signup" tabindex="0" class="registerLink" onclick=navigate('self')>${msg("registerHere")}</span>
                                                        <span>${msg("noAccount")} <a class="signUpLink" href="${url.registrationUrl}">${msg("doRegister")}</a></span>
                                                    </div>
                                                </div>
                                            </#if>
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                    <#--  <div class="ui column tablet only computer only"></div>  -->
                </div>
            </div>
        </div>
    </div>
    <script type="text/javascript">
        var slideIndex = 0;
        showSlides();

        function showSlides() {
		var i;
		var slides = document.getElementsByClassName("mySlides");
		var dots = document.getElementsByClassName("dot");
		for (i = 0; i < slides.length; i++) {
		    slides[i].style.display = "none";  
		}
		slideIndex++;
		if (slideIndex > slides.length) {slideIndex = 1}    
		for (i = 0; i < dots.length; i++) {
		    dots[i].className = dots[i].className.replace(" active", "");
		}
		slides[slideIndex-1].style.display = "block";  
		dots[slideIndex-1].className += " active";
		setTimeout(showSlides, 5000); // Change image every 5 seconds
        }

	function passwordOrOtp() {
                if (document.getElementById('usePasswordRB').checked) {
                    document.getElementById('usePasswordDiv').style.display = 'block';
                    document.getElementById('useOTPDiv').style.display = 'none';
                } else {
                    document.getElementById('usePasswordDiv').style.display = 'none';
                    document.getElementById('useOTPDiv').style.display = 'block';
                }
            }

    </script>
    </#if>
</#if>
</@layout.registrationLayout>