@echo off
mode con: cols=120 lines=30
color 3
title ICY Tweaker 75 KB Method
:bits1
cls
echo -----------------------------------------------=[{ICY TWEAKER 75 KB Method}]=--------------------------------------------------
echo.
echo.                                   
echo        __     ______     __  __        ______   __     __     ______     ______     __  __     ______     ______    
echo       /\ \   /\  ___\   /\ \_\ \      /\__  _\ /\ \  _ \ \   /\  ___\   /\  __ \   /\ \/ /    /\  ___\   /\  ^== \   
echo       \ \ \  \ \ \____  \ \____ \     \/_/\ \/ \ \ \/ ".\ \  \ \  __\   \ \  __ \  \ \  _"-.  \ \  __\   \ \  __^<   
echo        \ \_\  \ \_____\  \/\_____\       \ \_\  \ \__/"\ \_\  \ \_____\  \ \_\ \_\  \ \_\ \_\  \ \_____\  \ \_\ \_\ 
echo         \/_/   \/_____/   \/_____/        \/_/   \/_/   \/_/   \/_____/   \/_/\/_/   \/_/\/_/   \/_____/   \/_/ /_/ 
echo.                                                                                                              
echo.
echo.                                
echo ----------------------------------------------=[{By Micychalek and herzay}]=--------------------------------------------------
echo Dont close this while playing
ping 127.0.0.1 -n 4 >nul

sc query BITS | find /I "STATE" | find "STOPPED" >nul
goto :start >nul 

:start >nul 
sc start BITS >nul 
goto :bits1: >nul