--[[
#-------------------------------------------------------------------
# 宝塔Linux面板
#-------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
#-------------------------------------------------------------------
# Author: lkq@bt.cn 
# Time:2024-05-15
# 描述: ngx-lua html解析器
# 参考: Python html.parser
# 参考: Python html.unescape
#-------------------------------------------------------------------
]]--
local html_parser = {}

--# see http://www.w3.org/TR/html5/syntax.html#tokenizing-character-references
local _invalid_charrefs = {
    [0x00] = '\\ufffd',  -- REPLACEMENT CHARACTER
    [0x0d] = '\r',      -- CARRIAGE RETURN
    [0x80] = '\u{20ac}',-- EURO SIGN
    [0x81] = '\x81',    -- <control>
    [0x82] = '\u{201a}',-- SINGLE LOW-9 QUOTATION MARK
    [0x83] = '\u{0192}',-- LATIN SMALL LETTER F WITH HOOK
    [0x84] = '\u{201e}',-- DOUBLE LOW-9 QUOTATION MARK
    [0x85] = '\u{2026}',-- HORIZONTAL ELLIPSIS
    [0x86] = '\u{2020}',-- DAGGER
    [0x87] = '\u{2021}',-- DOUBLE DAGGER
    [0x88] = '\u{02c6}',-- MODIFIER LETTER CIRCUMFLEX ACCENT
    [0x89] = '\u{2030}',-- PER MILLE SIGN
    [0x8a] = '\u{0160}',-- LATIN CAPITAL LETTER S WITH CARON
    [0x8b] = '\u{2039}',-- SINGLE LEFT-POINTING ANGLE QUOTATION MARK
    [0x8c] = '\u{0152}',-- LATIN CAPITAL LIGATURE OE
    [0x8d] = '\x8d',    -- <control>
    [0x8e] = '\u{017d}',-- LATIN CAPITAL LETTER Z WITH CARON
    [0x8f] = '\x8f',    -- <control>
    [0x90] = '\x90',    -- <control>
    [0x91] = '\u{2018}',-- LEFT SINGLE QUOTATION MARK
    [0x92] = '\u{2019}',-- RIGHT SINGLE QUOTATION MARK
    [0x93] = '\u{201c}',-- LEFT DOUBLE QUOTATION MARK
    [0x94] = '\u{201d}',-- RIGHT DOUBLE QUOTATION MARK
    [0x95] = '\u{2022}',-- BULLET
    [0x96] = '\u{2013}',-- EN DASH
    [0x97] = '\u{2014}',-- EM DASH
    [0x98] = '\u{02dc}',-- SMALL TILDE
    [0x99] = '\u{2122}',-- TRADE MARK SIGN
    [0x9a] = '\u{0161}',-- LATIN SMALL LETTER S WITH CARON
    [0x9b] = '\u{203a}',-- SINGLE RIGHT-POINTING ANGLE QUOTATION MARK
    [0x9c] = '\u{0153}',-- LATIN SMALL LIGATURE OE
    [0x9d] = '\x9d',    -- <control>
    [0x9e] = '\u{017e}',-- LATIN SMALL LETTER Z WITH CARON
    [0x9f] = '\u{0178}',-- LATIN CAPITAL LETTER Y WITH DIAERESIS
}
local _invalid_codepoints ={
    --# 0x0001 to 0x0008
    [0x1]=true,[0x2]=true,[0x3]=true,[0x4]=true,
    [0x5]=true,[0x6]=true,[0x7]=true,[0x8]=true,
    -- # 0x000E to 0x001F
    [0xb]=true,[0xe]=true,[0xf]=true,[0x10]=true,
    [0x11]=true,[0x12]=true,[0x13]=true,[0x14]=true,
    [0x15]=true,[0x16]=true, [0x17]=true,[0x18]=true,
    [0x19]=true,[0x1a]=true,[0x1b]=true, [0x1c]=true,
    [0x1d]=true,[0x1e]=true,[0x1f]=true,
    --# 0x007F to 0x009F
    [0xffff]=true, [0x4ffff]=true,[0xcffff]=true,[0xafffe]=true,
    [0x9fffe]=true,[0xdfffe]=true, [0x8fffe]=true,[0xcfffe]=true,
    [0x9ffff]=true,[0x1ffff]=true,[0x5ffff]=true,[0xdffff]=true,
    [0x10fffe]=true,[0xefffe]=true,
    [0x7f]=true,[0x80]=true,[0x81]=true,[0x82]=true,[0x83]=true,
    [0x84]=true, [0x85]=true,[0x86]=true,[0x87]=true,[0x88]=true,
    [0x89]=true,[0x8a]=true,[0x8b]=true,[0x8c]=true,
    [0x8d]=true,[0x8e]=true,[0x8f]=true,[0x90]=true,[0x91]=true,
    [0x92]=true, [0x93]=true, [0x94]=true,[0x95]=true,
    [0x96]=true,[0x97]=true,[0x98]=true,[0x99]=true,[0x9a]=true,
    [0x9b]=true,[0x9c]=true,[0x9d]=true, [0x9e]=true, [0x9f]=true,
    --thers
    [0x6ffff]=true,[0xeffff]=true,[0xaffff]=true,[0x2ffff]=true,
    [0x7fffe]=true,[0xbfffe]=true,[0xfdd0]=true,[0xfdd1]=true,
    [0xfdd2]=true,[0xfdd3]=true,[0xfdd4]=true,[0xfdd5]=true,
    [0xfdd6]=true, [0xfdd7]=true,[0xfdd8]=true,[0xfdd9]=true,
    [0xfdda]=true,[0xfddb]=true,[0xfddc]=true,[0xfddd]=true,
    [0xfdde]=true,[0xfddf]=true,[0xfde0]=true,[0xfde1]=true,
    [0xfde2]=true,[0xfde3]=true,[0xfde4]=true,[0xfde5]=true,
    --  0xFDD0 to 0xFDEF
    [0xfde6]=true,[0x3ffff]=true,[0xbffff]=true,[0x7ffff]=true,
    [0xfffff]=true,[0xfde7]=true,[0xfde8]=true,[0xfde9]=true,
    [0xfdea]=true,[0xfdeb]=true,[0xfdec]=true,[0xfded]=true,
    [0xfdee]=true,[0xfdef]=true,[0x1fffe]=true,[0x2fffe]=true,
    [0x3fffe]=true,[0x4fffe]=true,[0x5fffe]=true,[0x8ffff]=true,
    [0x6fffe]=true,[0xffffe]=true,[0xfffe]=true,[0x10ffff]=true,
}

local html5={
["Aacute"] = '\u{c1}',["aacute"] = '\u{e1}',["Aacute;"] = '\u{c1}',["aacute;"] = '\u{e1}',
["Abreve;"] = '\u{102}',["abreve;"] = '\u{103}',["ac;"] = '\u{223e}',["acd;"] = '\u{223f}',["acE;"] = '\u{223e}\u{333}',
["Acirc"] = '\u{c2}',["acirc"] = '\u{e2}',["Acirc;"] = '\u{c2}',["acirc;"] = '\u{e2}',["acute"] = '\u{b4}',
["acute;"] = '\u{b4}',["Acy;"] = '\u{410}',["acy;"] = '\u{430}',["AElig"] = '\u{c6}',["aelig"] = '\u{e6}',
["AElig;"] = '\u{c6}',["aelig;"] = '\u{e6}',["af;"] = '\u{2061}',["Afr;"] = '\u{1d504}',["afr;"] = '\u{1d51e}',
["Agrave"] = '\u{c0}',["agrave"] = '\u{e0}',["Agrave;"] = '\u{c0}',["agrave;"] = '\u{e0}',["alefsym;"] = '\u{2135}',
["aleph;"] = '\u{2135}',["Alpha;"] = '\u{391}',["alpha;"] = '\u{3b1}',["Amacr;"] = '\u{100}',["amacr;"] = '\u{101}',
["amalg;"] = '\u{2a3f}',["AMP"] = '&',["amp"] = '&',["AMP;"] = '&',["amp;"] = '&',
["And;"] = '\u{2a53}',["and;"] = '\u{2227}',["andand;"] = '\u{2a55}',["andd;"] = '\u{2a5c}',["andslope;"] = '\u{2a58}',
["andv;"] = '\u{2a5a}',["ang;"] = '\u{2220}',["ange;"] = '\u{29a4}',["angle;"] = '\u{2220}',["angmsd;"] = '\u{2221}',
["angmsdaa;"] = '\u{29a8}',["angmsdab;"] = '\u{29a9}',["angmsdac;"] = '\u{29aa}',["angmsdad;"] = '\u{29ab}',["angmsdae;"] = '\u{29ac}',
["angmsdaf;"] = '\u{29ad}',["angmsdag;"] = '\u{29ae}',["angmsdah;"] = '\u{29af}',["angrt;"] = '\u{221f}',["angrtvb;"] = '\u{22be}',
["angrtvbd;"] = '\u{299d}',["angsph;"] = '\u{2222}',["angst;"] = '\u{c5}',["angzarr;"] = '\u{237c}',["Aogon;"] = '\u{104}',
["aogon;"] = '\u{105}',["Aopf;"] = '\u{1d538}',["aopf;"] = '\u{1d552}',["ap;"] = '\u{2248}',["apacir;"] = '\u{2a6f}',
["apE;"] = '\u{2a70}',["ape;"] = '\u{224a}',["apid;"] = '\u{224b}',["apos;"] = '\'',["ApplyFunction;"] = '\u{2061}',
["approx;"] = '\u{2248}',["approxeq;"] = '\u{224a}',["Aring"] = '\u{c5}',["aring"] = '\u{e5}',["Aring;"] = '\u{c5}',
["aring;"] = '\u{e5}',["Ascr;"] = '\u{1d49c}',["ascr;"] = '\u{1d4b6}',["Assign;"] = '\u{2254}',["ast;"] = '*',
["asymp;"] = '\u{2248}',["asympeq;"] = '\u{224d}',["Atilde"] = '\u{c3}',["atilde"] = '\u{e3}',["Atilde;"] = '\u{c3}',
["atilde;"] = '\u{e3}',["Auml"] = '\u{c4}',["auml"] = '\u{e4}',["Auml;"] = '\u{c4}',["auml;"] = '\u{e4}',
["awconint;"] = '\u{2233}',["awint;"] = '\u{2a11}',["backcong;"] = '\u{224c}',["backepsilon;"] = '\u{3f6}',["backprime;"] = '\u{2035}',
["backsim;"] = '\u{223d}',["backsimeq;"] = '\u{22cd}',["Backslash;"] = '\u{2216}',["Barv;"] = '\u{2ae7}',["barvee;"] = '\u{22bd}',
["Barwed;"] = '\u{2306}',["barwed;"] = '\u{2305}',["barwedge;"] = '\u{2305}',["bbrk;"] = '\u{23b5}',["bbrktbrk;"] = '\u{23b6}',
["bcong;"] = '\u{224c}',["Bcy;"] = '\u{411}',["bcy;"] = '\u{431}',["bdquo;"] = '\u{201e}',["becaus;"] = '\u{2235}',
["Because;"] = '\u{2235}',["because;"] = '\u{2235}',["bemptyv;"] = '\u{29b0}',["bepsi;"] = '\u{3f6}',["bernou;"] = '\u{212c}',
["Bernoullis;"] = '\u{212c}',["Beta;"] = '\u{392}',["beta;"] = '\u{3b2}',["beth;"] = '\u{2136}',["between;"] = '\u{226c}',
["Bfr;"] = '\u{1d505}',["bfr;"] = '\u{1d51f}',["bigcap;"] = '\u{22c2}',["bigcirc;"] = '\u{25ef}',["bigcup;"] = '\u{22c3}',
["bigodot;"] = '\u{2a00}',["bigoplus;"] = '\u{2a01}',["bigotimes;"] = '\u{2a02}',["bigsqcup;"] = '\u{2a06}',["bigstar;"] = '\u{2605}',
["bigtriangledown;"] = '\u{25bd}',["bigtriangleup;"] = '\u{25b3}',["biguplus;"] = '\u{2a04}',["bigvee;"] = '\u{22c1}',["bigwedge;"] = '\u{22c0}',
["bkarow;"] = '\u{290d}',["blacklozenge;"] = '\u{29eb}',["blacksquare;"] = '\u{25aa}',["blacktriangle;"] = '\u{25b4}',["blacktriangledown;"] = '\u{25be}',
["blacktriangleleft;"] = '\u{25c2}',["blacktriangleright;"] = '\u{25b8}',["blank;"] = '\u{2423}',["blk12;"] = '\u{2592}',["blk14;"] = '\u{2591}',
["blk34;"] = '\u{2593}',["block;"] = '\u{2588}',["bne;"] = '=\u{20e5}',["bnequiv;"] = '\u{2261}\u{20e5}',["bNot;"] = '\u{2aed}',
["bnot;"] = '\u{2310}',["Bopf;"] = '\u{1d539}',["bopf;"] = '\u{1d553}',["bot;"] = '\u{22a5}',["bottom;"] = '\u{22a5}',
["bowtie;"] = '\u{22c8}',["boxbox;"] = '\u{29c9}',["boxDL;"] = '\u{2557}',["boxDl;"] = '\u{2556}',["boxdL;"] = '\u{2555}',
["boxdl;"] = '\u{2510}',["boxDR;"] = '\u{2554}',["boxDr;"] = '\u{2553}',["boxdR;"] = '\u{2552}',["boxdr;"] = '\u{250c}',
["boxH;"] = '\u{2550}',["boxh;"] = '\u{2500}',["boxHD;"] = '\u{2566}',["boxHd;"] = '\u{2564}',["boxhD;"] = '\u{2565}',
["boxhd;"] = '\u{252c}',["boxHU;"] = '\u{2569}',["boxHu;"] = '\u{2567}',["boxhU;"] = '\u{2568}',["boxhu;"] = '\u{2534}',
["boxminus;"] = '\u{229f}',["boxplus;"] = '\u{229e}',["boxtimes;"] = '\u{22a0}',["boxUL;"] = '\u{255d}',["boxUl;"] = '\u{255c}',
["boxuL;"] = '\u{255b}',["boxul;"] = '\u{2518}',["boxUR;"] = '\u{255a}',["boxUr;"] = '\u{2559}',["boxuR;"] = '\u{2558}',
["boxur;"] = '\u{2514}',["boxV;"] = '\u{2551}',["boxv;"] = '\u{2502}',["boxVH;"] = '\u{256c}',["boxVh;"] = '\u{256b}',
["boxvH;"] = '\u{256a}',["boxvh;"] = '\u{253c}',["boxVL;"] = '\u{2563}',["boxVl;"] = '\u{2562}',["boxvL;"] = '\u{2561}',
["boxvl;"] = '\u{2524}',["boxVR;"] = '\u{2560}',["boxVr;"] = '\u{255f}',["boxvR;"] = '\u{255e}',["boxvr;"] = '\u{251c}',
["bprime;"] = '\u{2035}',["Breve;"] = '\u{2d8}',["breve;"] = '\u{2d8}',["brvbar"] = '\u{a6}',["brvbar;"] = '\u{a6}',
["Bscr;"] = '\u{212c}',["bscr;"] = '\u{1d4b7}',["bsemi;"] = '\u{204f}',["bsim;"] = '\u{223d}',["bsime;"] = '\u{22cd}',
["bsol;"] = '\\',["bsolb;"] = '\u{29c5}',["bsolhsub;"] = '\u{27c8}',["bull;"] = '\u{2022}',["bullet;"] = '\u{2022}',
["bump;"] = '\u{224e}',["bumpE;"] = '\u{2aae}',["bumpe;"] = '\u{224f}',["Bumpeq;"] = '\u{224e}',["bumpeq;"] = '\u{224f}',
["Cacute;"] = '\u{106}',["cacute;"] = '\u{107}',["Cap;"] = '\u{22d2}',["cap;"] = '\u{2229}',["capand;"] = '\u{2a44}',
["capbrcup;"] = '\u{2a49}',["capcap;"] = '\u{2a4b}',["capcup;"] = '\u{2a47}',["capdot;"] = '\u{2a40}',["CapitalDifferentialD;"] = '\u{2145}',
["caps;"] = '\u{2229}\u{fe00}',["caret;"] = '\u{2041}',["caron;"] = '\u{2c7}',["Cayleys;"] = '\u{212d}',["ccaps;"] = '\u{2a4d}',
["Ccaron;"] = '\u{10c}',["ccaron;"] = '\u{10d}',["Ccedil"] = '\u{c7}',["ccedil"] = '\u{e7}',["Ccedil;"] = '\u{c7}',
["ccedil;"] = '\u{e7}',["Ccirc;"] = '\u{108}',["ccirc;"] = '\u{109}',["Cconint;"] = '\u{2230}',["ccups;"] = '\u{2a4c}',
["ccupssm;"] = '\u{2a50}',["Cdot;"] = '\u{10a}',["cdot;"] = '\u{10b}',["cedil"] = '\u{b8}',["cedil;"] = '\u{b8}',
["Cedilla;"] = '\u{b8}',["cemptyv;"] = '\u{29b2}',["cent"] = '\u{a2}',["cent;"] = '\u{a2}',["CenterDot;"] = '\u{b7}',
["centerdot;"] = '\u{b7}',["Cfr;"] = '\u{212d}',["cfr;"] = '\u{1d520}',["CHcy;"] = '\u{427}',["chcy;"] = '\u{447}',
["check;"] = '\u{2713}',["checkmark;"] = '\u{2713}',["Chi;"] = '\u{3a7}',["chi;"] = '\u{3c7}',["cir;"] = '\u{25cb}',
["circ;"] = '\u{2c6}',["circeq;"] = '\u{2257}',["circlearrowleft;"] = '\u{21ba}',["circlearrowright;"] = '\u{21bb}',["circledast;"] = '\u{229b}',
["circledcirc;"] = '\u{229a}',["circleddash;"] = '\u{229d}',["CircleDot;"] = '\u{2299}',["circledR;"] = '\u{ae}',["circledS;"] = '\u{24c8}',
["CircleMinus;"] = '\u{2296}',["CirclePlus;"] = '\u{2295}',["CircleTimes;"] = '\u{2297}',["cirE;"] = '\u{29c3}',["cire;"] = '\u{2257}',
["cirfnint;"] = '\u{2a10}',["cirmid;"] = '\u{2aef}',["cirscir;"] = '\u{29c2}',["ClockwiseContourIntegral;"] = '\u{2232}',["CloseCurlyDoubleQuote;"] = '\u{201d}',
["CloseCurlyQuote;"] = '\u{2019}',["clubs;"] = '\u{2663}',["clubsuit;"] = '\u{2663}',["Colon;"] = '\u{2237}',["colon;"] = ':',
["Colone;"] = '\u{2a74}',["colone;"] = '\u{2254}',["coloneq;"] = '\u{2254}',["comma;"] = ',',["commat;"] = '@',
["comp;"] = '\u{2201}',["compfn;"] = '\u{2218}',["complement;"] = '\u{2201}',["complexes;"] = '\u{2102}',["cong;"] = '\u{2245}',
["congdot;"] = '\u{2a6d}',["Congruent;"] = '\u{2261}',["Conint;"] = '\u{222f}',["conint;"] = '\u{222e}',["ContourIntegral;"] = '\u{222e}',
["Copf;"] = '\u{2102}',["copf;"] = '\u{1d554}',["coprod;"] = '\u{2210}',["Coproduct;"] = '\u{2210}',["COPY"] = '\u{a9}',
["copy"] = '\u{a9}',["COPY;"] = '\u{a9}',["copy;"] = '\u{a9}',["copysr;"] = '\u{2117}',["CounterClockwiseContourIntegral;"] = '\u{2233}',
["crarr;"] = '\u{21b5}',["Cross;"] = '\u{2a2f}',["cross;"] = '\u{2717}',["Cscr;"] = '\u{1d49e}',["cscr;"] = '\u{1d4b8}',
["csub;"] = '\u{2acf}',["csube;"] = '\u{2ad1}',["csup;"] = '\u{2ad0}',["csupe;"] = '\u{2ad2}',["ctdot;"] = '\u{22ef}',
["cudarrl;"] = '\u{2938}',["cudarrr;"] = '\u{2935}',["cuepr;"] = '\u{22de}',["cuesc;"] = '\u{22df}',["cularr;"] = '\u{21b6}',
["cularrp;"] = '\u{293d}',["Cup;"] = '\u{22d3}',["cup;"] = '\u{222a}',["cupbrcap;"] = '\u{2a48}',["CupCap;"] = '\u{224d}',
["cupcap;"] = '\u{2a46}',["cupcup;"] = '\u{2a4a}',["cupdot;"] = '\u{228d}',["cupor;"] = '\u{2a45}',["cups;"] = '\u{222a}\u{fe00}',
["curarr;"] = '\u{21b7}',["curarrm;"] = '\u{293c}',["curlyeqprec;"] = '\u{22de}',["curlyeqsucc;"] = '\u{22df}',["curlyvee;"] = '\u{22ce}',
["curlywedge;"] = '\u{22cf}',["curren"] = '\u{a4}',["curren;"] = '\u{a4}',["curvearrowleft;"] = '\u{21b6}',["curvearrowright;"] = '\u{21b7}',
["cuvee;"] = '\u{22ce}',["cuwed;"] = '\u{22cf}',["cwconint;"] = '\u{2232}',["cwint;"] = '\u{2231}',["cylcty;"] = '\u{232d}',
["Dagger;"] = '\u{2021}',["dagger;"] = '\u{2020}',["daleth;"] = '\u{2138}',["Darr;"] = '\u{21a1}',["dArr;"] = '\u{21d3}',
["darr;"] = '\u{2193}',["dash;"] = '\u{2010}',["Dashv;"] = '\u{2ae4}',["dashv;"] = '\u{22a3}',["dbkarow;"] = '\u{290f}',
["dblac;"] = '\u{2dd}',["Dcaron;"] = '\u{10e}',["dcaron;"] = '\u{10f}',["Dcy;"] = '\u{414}',["dcy;"] = '\u{434}',
["DD;"] = '\u{2145}',["dd;"] = '\u{2146}',["ddagger;"] = '\u{2021}',["ddarr;"] = '\u{21ca}',["DDotrahd;"] = '\u{2911}',
["ddotseq;"] = '\u{2a77}',["deg"] = '\u{b0}',["deg;"] = '\u{b0}',["Del;"] = '\u{2207}',["Delta;"] = '\u{394}',
["delta;"] = '\u{3b4}',["demptyv;"] = '\u{29b1}',["dfisht;"] = '\u{297f}',["Dfr;"] = '\u{1d507}',["dfr;"] = '\u{1d521}',
["dHar;"] = '\u{2965}',["dharl;"] = '\u{21c3}',["dharr;"] = '\u{21c2}',["DiacriticalAcute;"] = '\u{b4}',["DiacriticalDot;"] = '\u{2d9}',
["DiacriticalDoubleAcute;"] = '\u{2dd}',["DiacriticalGrave;"] = '`',["DiacriticalTilde;"] = '\u{2dc}',["diam;"] = '\u{22c4}',["Diamond;"] = '\u{22c4}',
["diamond;"] = '\u{22c4}',["diamondsuit;"] = '\u{2666}',["diams;"] = '\u{2666}',["die;"] = '\u{a8}',["DifferentialD;"] = '\u{2146}',
["digamma;"] = '\u{3dd}',["disin;"] = '\u{22f2}',["div;"] = '\u{f7}',["divide"] = '\u{f7}',["divide;"] = '\u{f7}',
["divideontimes;"] = '\u{22c7}',["divonx;"] = '\u{22c7}',["DJcy;"] = '\u{402}',["djcy;"] = '\u{452}',["dlcorn;"] = '\u{231e}',
["dlcrop;"] = '\u{230d}',["dollar;"] = '$',["Dopf;"] = '\u{1d53b}',["dopf;"] = '\u{1d555}',["Dot;"] = '\u{a8}',
["dot;"] = '\u{2d9}',["DotDot;"] = '\u{20dc}',["doteq;"] = '\u{2250}',["doteqdot;"] = '\u{2251}',["DotEqual;"] = '\u{2250}',
["dotminus;"] = '\u{2238}',["dotplus;"] = '\u{2214}',["dotsquare;"] = '\u{22a1}',["doublebarwedge;"] = '\u{2306}',["DoubleContourIntegral;"] = '\u{222f}',
["DoubleDot;"] = '\u{a8}',["DoubleDownArrow;"] = '\u{21d3}',["DoubleLeftArrow;"] = '\u{21d0}',["DoubleLeftRightArrow;"] = '\u{21d4}',["DoubleLeftTee;"] = '\u{2ae4}',
["DoubleLongLeftArrow;"] = '\u{27f8}',["DoubleLongLeftRightArrow;"] = '\u{27fa}',["DoubleLongRightArrow;"] = '\u{27f9}',["DoubleRightArrow;"] = '\u{21d2}',["DoubleRightTee;"] = '\u{22a8}',
["DoubleUpArrow;"] = '\u{21d1}',["DoubleUpDownArrow;"] = '\u{21d5}',["DoubleVerticalBar;"] = '\u{2225}',["DownArrow;"] = '\u{2193}',["Downarrow;"] = '\u{21d3}',
["downarrow;"] = '\u{2193}',["DownArrowBar;"] = '\u{2913}',["DownArrowUpArrow;"] = '\u{21f5}',["DownBreve;"] = '\u{311}',["downdownarrows;"] = '\u{21ca}',
["downharpoonleft;"] = '\u{21c3}',["downharpoonright;"] = '\u{21c2}',["DownLeftRightVector;"] = '\u{2950}',["DownLeftTeeVector;"] = '\u{295e}',["DownLeftVector;"] = '\u{21bd}',
["DownLeftVectorBar;"] = '\u{2956}',["DownRightTeeVector;"] = '\u{295f}',["DownRightVector;"] = '\u{21c1}',["DownRightVectorBar;"] = '\u{2957}',["DownTee;"] = '\u{22a4}',
["DownTeeArrow;"] = '\u{21a7}',["drbkarow;"] = '\u{2910}',["drcorn;"] = '\u{231f}',["drcrop;"] = '\u{230c}',["Dscr;"] = '\u{1d49f}',
["dscr;"] = '\u{1d4b9}',["DScy;"] = '\u{405}',["dscy;"] = '\u{455}',["dsol;"] = '\u{29f6}',["Dstrok;"] = '\u{110}',
["dstrok;"] = '\u{111}',["dtdot;"] = '\u{22f1}',["dtri;"] = '\u{25bf}',["dtrif;"] = '\u{25be}',["duarr;"] = '\u{21f5}',
["duhar;"] = '\u{296f}',["dwangle;"] = '\u{29a6}',["DZcy;"] = '\u{40f}',["dzcy;"] = '\u{45f}',["dzigrarr;"] = '\u{27ff}',
["Eacute"] = '\u{c9}',["eacute"] = '\u{e9}',["Eacute;"] = '\u{c9}',["eacute;"] = '\u{e9}',["easter;"] = '\u{2a6e}',
["Ecaron;"] = '\u{11a}',["ecaron;"] = '\u{11b}',["ecir;"] = '\u{2256}',["Ecirc"] = '\u{ca}',["ecirc"] = '\u{ea}',
["Ecirc;"] = '\u{ca}',["ecirc;"] = '\u{ea}',["ecolon;"] = '\u{2255}',["Ecy;"] = '\u{42d}',["ecy;"] = '\u{44d}',
["eDDot;"] = '\u{2a77}',["Edot;"] = '\u{116}',["eDot;"] = '\u{2251}',["edot;"] = '\u{117}',["ee;"] = '\u{2147}',
["efDot;"] = '\u{2252}',["Efr;"] = '\u{1d508}',["efr;"] = '\u{1d522}',["eg;"] = '\u{2a9a}',["Egrave"] = '\u{c8}',
["egrave"] = '\u{e8}',["Egrave;"] = '\u{c8}',["egrave;"] = '\u{e8}',["egs;"] = '\u{2a96}',["egsdot;"] = '\u{2a98}',
["el;"] = '\u{2a99}',["Element;"] = '\u{2208}',["elinters;"] = '\u{23e7}',["ell;"] = '\u{2113}',["els;"] = '\u{2a95}',
["elsdot;"] = '\u{2a97}',["Emacr;"] = '\u{112}',["emacr;"] = '\u{113}',["empty;"] = '\u{2205}',["emptyset;"] = '\u{2205}',
["EmptySmallSquare;"] = '\u{25fb}',["emptyv;"] = '\u{2205}',["EmptyVerySmallSquare;"] = '\u{25ab}',["emsp13;"] = '\u{2004}',["emsp14;"] = '\u{2005}',
["emsp;"] = '\u{2003}',["ENG;"] = '\u{14a}',["eng;"] = '\u{14b}',["ensp;"] = '\u{2002}',["Eogon;"] = '\u{118}',
["eogon;"] = '\u{119}',["Eopf;"] = '\u{1d53c}',["eopf;"] = '\u{1d556}',["epar;"] = '\u{22d5}',["eparsl;"] = '\u{29e3}',
["eplus;"] = '\u{2a71}',["epsi;"] = '\u{3b5}',["Epsilon;"] = '\u{395}',["epsilon;"] = '\u{3b5}',["epsiv;"] = '\u{3f5}',
["eqcirc;"] = '\u{2256}',["eqcolon;"] = '\u{2255}',["eqsim;"] = '\u{2242}',["eqslantgtr;"] = '\u{2a96}',["eqslantless;"] = '\u{2a95}',
["Equal;"] = '\u{2a75}',["equals;"] = '=',["EqualTilde;"] = '\u{2242}',["equest;"] = '\u{225f}',["Equilibrium;"] = '\u{21cc}',
["equiv;"] = '\u{2261}',["equivDD;"] = '\u{2a78}',["eqvparsl;"] = '\u{29e5}',["erarr;"] = '\u{2971}',["erDot;"] = '\u{2253}',
["Escr;"] = '\u{2130}',["escr;"] = '\u{212f}',["esdot;"] = '\u{2250}',["Esim;"] = '\u{2a73}',["esim;"] = '\u{2242}',
["Eta;"] = '\u{397}',["eta;"] = '\u{3b7}',["ETH"] = '\u{d0}',["eth"] = '\u{f0}',["ETH;"] = '\u{d0}',
["eth;"] = '\u{f0}',["Euml"] = '\u{cb}',["euml"] = '\u{eb}',["Euml;"] = '\u{cb}',["euml;"] = '\u{eb}',
["euro;"] = '\u{20ac}',["excl;"] = '!',["exist;"] = '\u{2203}',["Exists;"] = '\u{2203}',["expectation;"] = '\u{2130}',
["ExponentialE;"] = '\u{2147}',["exponentiale;"] = '\u{2147}',["fallingdotseq;"] = '\u{2252}',["Fcy;"] = '\u{424}',["fcy;"] = '\u{444}',
["female;"] = '\u{2640}',["ffilig;"] = '\u{fb03}',["fflig;"] = '\u{fb00}',["ffllig;"] = '\u{fb04}',["Ffr;"] = '\u{1d509}',
["ffr;"] = '\u{1d523}',["filig;"] = '\u{fb01}',["FilledSmallSquare;"] = '\u{25fc}',["FilledVerySmallSquare;"] = '\u{25aa}',["fjlig;"] = 'fj',
["flat;"] = '\u{266d}',["fllig;"] = '\u{fb02}',["fltns;"] = '\u{25b1}',["fnof;"] = '\u{192}',["Fopf;"] = '\u{1d53d}',
["fopf;"] = '\u{1d557}',["ForAll;"] = '\u{2200}',["forall;"] = '\u{2200}',["fork;"] = '\u{22d4}',["forkv;"] = '\u{2ad9}',
["Fouriertrf;"] = '\u{2131}',["fpartint;"] = '\u{2a0d}',["frac12"] = '\u{bd}',["frac12;"] = '\u{bd}',["frac13;"] = '\u{2153}',
["frac14"] = '\u{bc}',["frac14;"] = '\u{bc}',["frac15;"] = '\u{2155}',["frac16;"] = '\u{2159}',["frac18;"] = '\u{215b}',
["frac23;"] = '\u{2154}',["frac25;"] = '\u{2156}',["frac34"] = '\u{be}',["frac34;"] = '\u{be}',["frac35;"] = '\u{2157}',
["frac38;"] = '\u{215c}',["frac45;"] = '\u{2158}',["frac56;"] = '\u{215a}',["frac58;"] = '\u{215d}',["frac78;"] = '\u{215e}',
["frasl;"] = '\u{2044}',["frown;"] = '\u{2322}',["Fscr;"] = '\u{2131}',["fscr;"] = '\u{1d4bb}',["gacute;"] = '\u{1f5}',
["Gamma;"] = '\u{393}',["gamma;"] = '\u{3b3}',["Gammad;"] = '\u{3dc}',["gammad;"] = '\u{3dd}',["gap;"] = '\u{2a86}',
["Gbreve;"] = '\u{11e}',["gbreve;"] = '\u{11f}',["Gcedil;"] = '\u{122}',["Gcirc;"] = '\u{11c}',["gcirc;"] = '\u{11d}',
["Gcy;"] = '\u{413}',["gcy;"] = '\u{433}',["Gdot;"] = '\u{120}',["gdot;"] = '\u{121}',["gE;"] = '\u{2267}',
["ge;"] = '\u{2265}',["gEl;"] = '\u{2a8c}',["gel;"] = '\u{22db}',["geq;"] = '\u{2265}',["geqq;"] = '\u{2267}',
["geqslant;"] = '\u{2a7e}',["ges;"] = '\u{2a7e}',["gescc;"] = '\u{2aa9}',["gesdot;"] = '\u{2a80}',["gesdoto;"] = '\u{2a82}',
["gesdotol;"] = '\u{2a84}',["gesl;"] = '\u{22db}\u{fe00}',["gesles;"] = '\u{2a94}',["Gfr;"] = '\u{1d50a}',["gfr;"] = '\u{1d524}',
["Gg;"] = '\u{22d9}',["gg;"] = '\u{226b}',["ggg;"] = '\u{22d9}',["gimel;"] = '\u{2137}',["GJcy;"] = '\u{403}',
["gjcy;"] = '\u{453}',["gl;"] = '\u{2277}',["gla;"] = '\u{2aa5}',["glE;"] = '\u{2a92}',["glj;"] = '\u{2aa4}',
["gnap;"] = '\u{2a8a}',["gnapprox;"] = '\u{2a8a}',["gnE;"] = '\u{2269}',["gne;"] = '\u{2a88}',["gneq;"] = '\u{2a88}',
["gneqq;"] = '\u{2269}',["gnsim;"] = '\u{22e7}',["Gopf;"] = '\u{1d53e}',["gopf;"] = '\u{1d558}',["grave;"] = '`',
["GreaterEqual;"] = '\u{2265}',["GreaterEqualLess;"] = '\u{22db}',["GreaterFullEqual;"] = '\u{2267}',["GreaterGreater;"] = '\u{2aa2}',["GreaterLess;"] = '\u{2277}',
["GreaterSlantEqual;"] = '\u{2a7e}',["GreaterTilde;"] = '\u{2273}',["Gscr;"] = '\u{1d4a2}',["gscr;"] = '\u{210a}',["gsim;"] = '\u{2273}',
["gsime;"] = '\u{2a8e}',["gsiml;"] = '\u{2a90}',["GT"] = '>',["gt"] = '>',["GT;"] = '>',
["Gt;"] = '\u{226b}',["gt;"] = '>',["gtcc;"] = '\u{2aa7}',["gtcir;"] = '\u{2a7a}',["gtdot;"] = '\u{22d7}',
["gtlPar;"] = '\u{2995}',["gtquest;"] = '\u{2a7c}',["gtrapprox;"] = '\u{2a86}',["gtrarr;"] = '\u{2978}',["gtrdot;"] = '\u{22d7}',
["gtreqless;"] = '\u{22db}',["gtreqqless;"] = '\u{2a8c}',["gtrless;"] = '\u{2277}',["gtrsim;"] = '\u{2273}',["gvertneqq;"] = '\u{2269}\u{fe00}',
["gvnE;"] = '\u{2269}\u{fe00}',["Hacek;"] = '\u{2c7}',["hairsp;"] = '\u{200a}',["half;"] = '\u{bd}',["hamilt;"] = '\u{210b}',
["HARDcy;"] = '\u{42a}',["hardcy;"] = '\u{44a}',["hArr;"] = '\u{21d4}',["harr;"] = '\u{2194}',["harrcir;"] = '\u{2948}',
["harrw;"] = '\u{21ad}',["Hat;"] = '^',["hbar;"] = '\u{210f}',["Hcirc;"] = '\u{124}',["hcirc;"] = '\u{125}',
["hearts;"] = '\u{2665}',["heartsuit;"] = '\u{2665}',["hellip;"] = '\u{2026}',["hercon;"] = '\u{22b9}',["Hfr;"] = '\u{210c}',
["hfr;"] = '\u{1d525}',["HilbertSpace;"] = '\u{210b}',["hksearow;"] = '\u{2925}',["hkswarow;"] = '\u{2926}',["hoarr;"] = '\u{21ff}',
["homtht;"] = '\u{223b}',["hookleftarrow;"] = '\u{21a9}',["hookrightarrow;"] = '\u{21aa}',["Hopf;"] = '\u{210d}',["hopf;"] = '\u{1d559}',
["horbar;"] = '\u{2015}',["HorizontalLine;"] = '\u{2500}',["Hscr;"] = '\u{210b}',["hscr;"] = '\u{1d4bd}',["hslash;"] = '\u{210f}',
["Hstrok;"] = '\u{126}',["hstrok;"] = '\u{127}',["HumpDownHump;"] = '\u{224e}',["HumpEqual;"] = '\u{224f}',["hybull;"] = '\u{2043}',
["hyphen;"] = '\u{2010}',["Iacute"] = '\u{cd}',["iacute"] = '\u{ed}',["Iacute;"] = '\u{cd}',["iacute;"] = '\u{ed}',
["ic;"] = '\u{2063}',["Icirc"] = '\u{ce}',["icirc"] = '\u{ee}',["Icirc;"] = '\u{ce}',["icirc;"] = '\u{ee}',
["Icy;"] = '\u{418}',["icy;"] = '\u{438}',["Idot;"] = '\u{130}',["IEcy;"] = '\u{415}',["iecy;"] = '\u{435}',
["iexcl"] = '\u{a1}',["iexcl;"] = '\u{a1}',["iff;"] = '\u{21d4}',["Ifr;"] = '\u{2111}',["ifr;"] = '\u{1d526}',
["Igrave"] = '\u{cc}',["igrave"] = '\u{ec}',["Igrave;"] = '\u{cc}',["igrave;"] = '\u{ec}',["ii;"] = '\u{2148}',
["iiiint;"] = '\u{2a0c}',["iiint;"] = '\u{222d}',["iinfin;"] = '\u{29dc}',["iiota;"] = '\u{2129}',["IJlig;"] = '\u{132}',
["ijlig;"] = '\u{133}',["Im;"] = '\u{2111}',["Imacr;"] = '\u{12a}',["imacr;"] = '\u{12b}',["image;"] = '\u{2111}',
["ImaginaryI;"] = '\u{2148}',["imagline;"] = '\u{2110}',["imagpart;"] = '\u{2111}',["imath;"] = '\u{131}',["imof;"] = '\u{22b7}',
["imped;"] = '\u{1b5}',["Implies;"] = '\u{21d2}',["in;"] = '\u{2208}',["incare;"] = '\u{2105}',["infin;"] = '\u{221e}',
["infintie;"] = '\u{29dd}',["inodot;"] = '\u{131}',["Int;"] = '\u{222c}',["int;"] = '\u{222b}',["intcal;"] = '\u{22ba}',
["integers;"] = '\u{2124}',["Integral;"] = '\u{222b}',["intercal;"] = '\u{22ba}',["Intersection;"] = '\u{22c2}',["intlarhk;"] = '\u{2a17}',
["intprod;"] = '\u{2a3c}',["InvisibleComma;"] = '\u{2063}',["InvisibleTimes;"] = '\u{2062}',["IOcy;"] = '\u{401}',["iocy;"] = '\u{451}',
["Iogon;"] = '\u{12e}',["iogon;"] = '\u{12f}',["Iopf;"] = '\u{1d540}',["iopf;"] = '\u{1d55a}',["Iota;"] = '\u{399}',
["iota;"] = '\u{3b9}',["iprod;"] = '\u{2a3c}',["iquest"] = '\u{bf}',["iquest;"] = '\u{bf}',["Iscr;"] = '\u{2110}',
["iscr;"] = '\u{1d4be}',["isin;"] = '\u{2208}',["isindot;"] = '\u{22f5}',["isinE;"] = '\u{22f9}',["isins;"] = '\u{22f4}',
["isinsv;"] = '\u{22f3}',["isinv;"] = '\u{2208}',["it;"] = '\u{2062}',["Itilde;"] = '\u{128}',["itilde;"] = '\u{129}',
["Iukcy;"] = '\u{406}',["iukcy;"] = '\u{456}',["Iuml"] = '\u{cf}',["iuml"] = '\u{ef}',["Iuml;"] = '\u{cf}',
["iuml;"] = '\u{ef}',["Jcirc;"] = '\u{134}',["jcirc;"] = '\u{135}',["Jcy;"] = '\u{419}',["jcy;"] = '\u{439}',
["Jfr;"] = '\u{1d50d}',["jfr;"] = '\u{1d527}',["jmath;"] = '\u{237}',["Jopf;"] = '\u{1d541}',["jopf;"] = '\u{1d55b}',
["Jscr;"] = '\u{1d4a5}',["jscr;"] = '\u{1d4bf}',["Jsercy;"] = '\u{408}',["jsercy;"] = '\u{458}',["Jukcy;"] = '\u{404}',
["jukcy;"] = '\u{454}',["Kappa;"] = '\u{39a}',["kappa;"] = '\u{3ba}',["kappav;"] = '\u{3f0}',["Kcedil;"] = '\u{136}',
["kcedil;"] = '\u{137}',["Kcy;"] = '\u{41a}',["kcy;"] = '\u{43a}',["Kfr;"] = '\u{1d50e}',["kfr;"] = '\u{1d528}',
["kgreen;"] = '\u{138}',["KHcy;"] = '\u{425}',["khcy;"] = '\u{445}',["KJcy;"] = '\u{40c}',["kjcy;"] = '\u{45c}',
["Kopf;"] = '\u{1d542}',["kopf;"] = '\u{1d55c}',["Kscr;"] = '\u{1d4a6}',["kscr;"] = '\u{1d4c0}',["lAarr;"] = '\u{21da}',
["Lacute;"] = '\u{139}',["lacute;"] = '\u{13a}',["laemptyv;"] = '\u{29b4}',["lagran;"] = '\u{2112}',["Lambda;"] = '\u{39b}',
["lambda;"] = '\u{3bb}',["Lang;"] = '\u{27ea}',["lang;"] = '\u{27e8}',["langd;"] = '\u{2991}',["langle;"] = '\u{27e8}',
["lap;"] = '\u{2a85}',["Laplacetrf;"] = '\u{2112}',["laquo"] = '\u{ab}',["laquo;"] = '\u{ab}',["Larr;"] = '\u{219e}',
["lArr;"] = '\u{21d0}',["larr;"] = '\u{2190}',["larrb;"] = '\u{21e4}',["larrbfs;"] = '\u{291f}',["larrfs;"] = '\u{291d}',
["larrhk;"] = '\u{21a9}',["larrlp;"] = '\u{21ab}',["larrpl;"] = '\u{2939}',["larrsim;"] = '\u{2973}',["larrtl;"] = '\u{21a2}',
["lat;"] = '\u{2aab}',["lAtail;"] = '\u{291b}',["latail;"] = '\u{2919}',["late;"] = '\u{2aad}',["lates;"] = '\u{2aad}\u{fe00}',
["lBarr;"] = '\u{290e}',["lbarr;"] = '\u{290c}',["lbbrk;"] = '\u{2772}',["lbrace;"] = '{',["lbrack;"] = '[',
["lbrke;"] = '\u{298b}',["lbrksld;"] = '\u{298f}',["lbrkslu;"] = '\u{298d}',["Lcaron;"] = '\u{13d}',["lcaron;"] = '\u{13e}',
["Lcedil;"] = '\u{13b}',["lcedil;"] = '\u{13c}',["lceil;"] = '\u{2308}',["lcub;"] = '{',["Lcy;"] = '\u{41b}',
["lcy;"] = '\u{43b}',["ldca;"] = '\u{2936}',["ldquo;"] = '\u{201c}',["ldquor;"] = '\u{201e}',["ldrdhar;"] = '\u{2967}',
["ldrushar;"] = '\u{294b}',["ldsh;"] = '\u{21b2}',["lE;"] = '\u{2266}',["le;"] = '\u{2264}',["LeftAngleBracket;"] = '\u{27e8}',
["LeftArrow;"] = '\u{2190}',["Leftarrow;"] = '\u{21d0}',["leftarrow;"] = '\u{2190}',["LeftArrowBar;"] = '\u{21e4}',["LeftArrowRightArrow;"] = '\u{21c6}',
["leftarrowtail;"] = '\u{21a2}',["LeftCeiling;"] = '\u{2308}',["LeftDoubleBracket;"] = '\u{27e6}',["LeftDownTeeVector;"] = '\u{2961}',["LeftDownVector;"] = '\u{21c3}',
["LeftDownVectorBar;"] = '\u{2959}',["LeftFloor;"] = '\u{230a}',["leftharpoondown;"] = '\u{21bd}',["leftharpoonup;"] = '\u{21bc}',["leftleftarrows;"] = '\u{21c7}',
["LeftRightArrow;"] = '\u{2194}',["Leftrightarrow;"] = '\u{21d4}',["leftrightarrow;"] = '\u{2194}',["leftrightarrows;"] = '\u{21c6}',["leftrightharpoons;"] = '\u{21cb}',
["leftrightsquigarrow;"] = '\u{21ad}',["LeftRightVector;"] = '\u{294e}',["LeftTee;"] = '\u{22a3}',["LeftTeeArrow;"] = '\u{21a4}',["LeftTeeVector;"] = '\u{295a}',
["leftthreetimes;"] = '\u{22cb}',["LeftTriangle;"] = '\u{22b2}',["LeftTriangleBar;"] = '\u{29cf}',["LeftTriangleEqual;"] = '\u{22b4}',["LeftUpDownVector;"] = '\u{2951}',
["LeftUpTeeVector;"] = '\u{2960}',["LeftUpVector;"] = '\u{21bf}',["LeftUpVectorBar;"] = '\u{2958}',["LeftVector;"] = '\u{21bc}',["LeftVectorBar;"] = '\u{2952}',
["lEg;"] = '\u{2a8b}',["leg;"] = '\u{22da}',["leq;"] = '\u{2264}',["leqq;"] = '\u{2266}',["leqslant;"] = '\u{2a7d}',
["les;"] = '\u{2a7d}',["lescc;"] = '\u{2aa8}',["lesdot;"] = '\u{2a7f}',["lesdoto;"] = '\u{2a81}',["lesdotor;"] = '\u{2a83}',
["lesg;"] = '\u{22da}\u{fe00}',["lesges;"] = '\u{2a93}',["lessapprox;"] = '\u{2a85}',["lessdot;"] = '\u{22d6}',["lesseqgtr;"] = '\u{22da}',
["lesseqqgtr;"] = '\u{2a8b}',["LessEqualGreater;"] = '\u{22da}',["LessFullEqual;"] = '\u{2266}',["LessGreater;"] = '\u{2276}',["lessgtr;"] = '\u{2276}',
["LessLess;"] = '\u{2aa1}',["lesssim;"] = '\u{2272}',["LessSlantEqual;"] = '\u{2a7d}',["LessTilde;"] = '\u{2272}',["lfisht;"] = '\u{297c}',
["lfloor;"] = '\u{230a}',["Lfr;"] = '\u{1d50f}',["lfr;"] = '\u{1d529}',["lg;"] = '\u{2276}',["lgE;"] = '\u{2a91}',
["lHar;"] = '\u{2962}',["lhard;"] = '\u{21bd}',["lharu;"] = '\u{21bc}',["lharul;"] = '\u{296a}',["lhblk;"] = '\u{2584}',
["LJcy;"] = '\u{409}',["ljcy;"] = '\u{459}',["Ll;"] = '\u{22d8}',["ll;"] = '\u{226a}',["llarr;"] = '\u{21c7}',
["llcorner;"] = '\u{231e}',["Lleftarrow;"] = '\u{21da}',["llhard;"] = '\u{296b}',["lltri;"] = '\u{25fa}',["Lmidot;"] = '\u{13f}',
["lmidot;"] = '\u{140}',["lmoust;"] = '\u{23b0}',["lmoustache;"] = '\u{23b0}',["lnap;"] = '\u{2a89}',["lnapprox;"] = '\u{2a89}',
["lnE;"] = '\u{2268}',["lne;"] = '\u{2a87}',["lneq;"] = '\u{2a87}',["lneqq;"] = '\u{2268}',["lnsim;"] = '\u{22e6}',
["loang;"] = '\u{27ec}',["loarr;"] = '\u{21fd}',["lobrk;"] = '\u{27e6}',["LongLeftArrow;"] = '\u{27f5}',["Longleftarrow;"] = '\u{27f8}',
["longleftarrow;"] = '\u{27f5}',["LongLeftRightArrow;"] = '\u{27f7}',["Longleftrightarrow;"] = '\u{27fa}',["longleftrightarrow;"] = '\u{27f7}',["longmapsto;"] = '\u{27fc}',
["LongRightArrow;"] = '\u{27f6}',["Longrightarrow;"] = '\u{27f9}',["longrightarrow;"] = '\u{27f6}',["looparrowleft;"] = '\u{21ab}',["looparrowright;"] = '\u{21ac}',
["lopar;"] = '\u{2985}',["Lopf;"] = '\u{1d543}',["lopf;"] = '\u{1d55d}',["loplus;"] = '\u{2a2d}',["lotimes;"] = '\u{2a34}',
["lowast;"] = '\u{2217}',["lowbar;"] = '_',["LowerLeftArrow;"] = '\u{2199}',["LowerRightArrow;"] = '\u{2198}',["loz;"] = '\u{25ca}',
["lozenge;"] = '\u{25ca}',["lozf;"] = '\u{29eb}',["lpar;"] = '(',["lparlt;"] = '\u{2993}',["lrarr;"] = '\u{21c6}',
["lrcorner;"] = '\u{231f}',["lrhar;"] = '\u{21cb}',["lrhard;"] = '\u{296d}',["lrm;"] = '\u{200e}',["lrtri;"] = '\u{22bf}',
["lsaquo;"] = '\u{2039}',["Lscr;"] = '\u{2112}',["lscr;"] = '\u{1d4c1}',["Lsh;"] = '\u{21b0}',["lsh;"] = '\u{21b0}',
["lsim;"] = '\u{2272}',["lsime;"] = '\u{2a8d}',["lsimg;"] = '\u{2a8f}',["lsqb;"] = '[',["lsquo;"] = '\u{2018}',
["lsquor;"] = '\u{201a}',["Lstrok;"] = '\u{141}',["lstrok;"] = '\u{142}',["LT"] = '<',["lt"] = '<',
["LT;"] = '<',["Lt;"] = '\u{226a}',["lt;"] = '<',["ltcc;"] = '\u{2aa6}',["ltcir;"] = '\u{2a79}',
["ltdot;"] = '\u{22d6}',["lthree;"] = '\u{22cb}',["ltimes;"] = '\u{22c9}',["ltlarr;"] = '\u{2976}',["ltquest;"] = '\u{2a7b}',
["ltri;"] = '\u{25c3}',["ltrie;"] = '\u{22b4}',["ltrif;"] = '\u{25c2}',["ltrPar;"] = '\u{2996}',["lurdshar;"] = '\u{294a}',
["luruhar;"] = '\u{2966}',["lvertneqq;"] = '\u{2268}\u{fe00}',["lvnE;"] = '\u{2268}\u{fe00}',["macr"] = '\u{af}',["macr;"] = '\u{af}',
["male;"] = '\u{2642}',["malt;"] = '\u{2720}',["maltese;"] = '\u{2720}',["Map;"] = '\u{2905}',["map;"] = '\u{21a6}',
["mapsto;"] = '\u{21a6}',["mapstodown;"] = '\u{21a7}',["mapstoleft;"] = '\u{21a4}',["mapstoup;"] = '\u{21a5}',["marker;"] = '\u{25ae}',
["mcomma;"] = '\u{2a29}',["Mcy;"] = '\u{41c}',["mcy;"] = '\u{43c}',["mdash;"] = '\u{2014}',["mDDot;"] = '\u{223a}',
["measuredangle;"] = '\u{2221}',["MediumSpace;"] = '\u{205f}',["Mellintrf;"] = '\u{2133}',["Mfr;"] = '\u{1d510}',["mfr;"] = '\u{1d52a}',
["mho;"] = '\u{2127}',["micro"] = '\u{b5}',["micro;"] = '\u{b5}',["mid;"] = '\u{2223}',["midast;"] = '*',
["midcir;"] = '\u{2af0}',["middot"] = '\u{b7}',["middot;"] = '\u{b7}',["minus;"] = '\u{2212}',["minusb;"] = '\u{229f}',
["minusd;"] = '\u{2238}',["minusdu;"] = '\u{2a2a}',["MinusPlus;"] = '\u{2213}',["mlcp;"] = '\u{2adb}',["mldr;"] = '\u{2026}',
["mnplus;"] = '\u{2213}',["models;"] = '\u{22a7}',["Mopf;"] = '\u{1d544}',["mopf;"] = '\u{1d55e}',["mp;"] = '\u{2213}',
["Mscr;"] = '\u{2133}',["mscr;"] = '\u{1d4c2}',["mstpos;"] = '\u{223e}',["Mu;"] = '\u{39c}',["mu;"] = '\u{3bc}',
["multimap;"] = '\u{22b8}',["mumap;"] = '\u{22b8}',["nabla;"] = '\u{2207}',["Nacute;"] = '\u{143}',["nacute;"] = '\u{144}',
["nang;"] = '\u{2220}\u{20d2}',["nap;"] = '\u{2249}',["napE;"] = '\u{2a70}\u{338}',["napid;"] = '\u{224b}\u{338}',["napos;"] = '\u{149}',
["napprox;"] = '\u{2249}',["natur;"] = '\u{266e}',["natural;"] = '\u{266e}',["naturals;"] = '\u{2115}',["nbsp"] = '\u{a0}',
["nbsp;"] = '\u{a0}',["nbump;"] = '\u{224e}\u{338}',["nbumpe;"] = '\u{224f}\u{338}',["ncap;"] = '\u{2a43}',["Ncaron;"] = '\u{147}',
["ncaron;"] = '\u{148}',["Ncedil;"] = '\u{145}',["ncedil;"] = '\u{146}',["ncong;"] = '\u{2247}',["ncongdot;"] = '\u{2a6d}\u{338}',
["ncup;"] = '\u{2a42}',["Ncy;"] = '\u{41d}',["ncy;"] = '\u{43d}',["ndash;"] = '\u{2013}',["ne;"] = '\u{2260}',
["nearhk;"] = '\u{2924}',["neArr;"] = '\u{21d7}',["nearr;"] = '\u{2197}',["nearrow;"] = '\u{2197}',["nedot;"] = '\u{2250}\u{338}',
["NegativeMediumSpace;"] = '\u{200b}',["NegativeThickSpace;"] = '\u{200b}',["NegativeThinSpace;"] = '\u{200b}',["NegativeVeryThinSpace;"] = '\u{200b}',["nequiv;"] = '\u{2262}',
["nesear;"] = '\u{2928}',["nesim;"] = '\u{2242}\u{338}',["NestedGreaterGreater;"] = '\u{226b}',["NestedLessLess;"] = '\u{226a}',["NewLine;"] = '',
["nexist;"] = '\u{2204}',["nexists;"] = '\u{2204}',["Nfr;"] = '\u{1d511}',["nfr;"] = '\u{1d52b}',["ngE;"] = '\u{2267}\u{338}',
["nge;"] = '\u{2271}',["ngeq;"] = '\u{2271}',["ngeqq;"] = '\u{2267}\u{338}',["ngeqslant;"] = '\u{2a7e}\u{338}',["nges;"] = '\u{2a7e}\u{338}',
["nGg;"] = '\u{22d9}\u{338}',["ngsim;"] = '\u{2275}',["nGt;"] = '\u{226b}\u{20d2}',["ngt;"] = '\u{226f}',["ngtr;"] = '\u{226f}',
["nGtv;"] = '\u{226b}\u{338}',["nhArr;"] = '\u{21ce}',["nharr;"] = '\u{21ae}',["nhpar;"] = '\u{2af2}',["ni;"] = '\u{220b}',
["nis;"] = '\u{22fc}',["nisd;"] = '\u{22fa}',["niv;"] = '\u{220b}',["NJcy;"] = '\u{40a}',["njcy;"] = '\u{45a}',
["nlArr;"] = '\u{21cd}',["nlarr;"] = '\u{219a}',["nldr;"] = '\u{2025}',["nlE;"] = '\u{2266}\u{338}',["nle;"] = '\u{2270}',
["nLeftarrow;"] = '\u{21cd}',["nleftarrow;"] = '\u{219a}',["nLeftrightarrow;"] = '\u{21ce}',["nleftrightarrow;"] = '\u{21ae}',["nleq;"] = '\u{2270}',
["nleqq;"] = '\u{2266}\u{338}',["nleqslant;"] = '\u{2a7d}\u{338}',["nles;"] = '\u{2a7d}\u{338}',["nless;"] = '\u{226e}',["nLl;"] = '\u{22d8}\u{338}',
["nlsim;"] = '\u{2274}',["nLt;"] = '\u{226a}\u{20d2}',["nlt;"] = '\u{226e}',["nltri;"] = '\u{22ea}',["nltrie;"] = '\u{22ec}',
["nLtv;"] = '\u{226a}\u{338}',["nmid;"] = '\u{2224}',["NoBreak;"] = '\u{2060}',["NonBreakingSpace;"] = '\u{a0}',["Nopf;"] = '\u{2115}',
["nopf;"] = '\u{1d55f}',["not"] = '\u{ac}',["Not;"] = '\u{2aec}',["not;"] = '\u{ac}',["NotCongruent;"] = '\u{2262}',
["NotCupCap;"] = '\u{226d}',["NotDoubleVerticalBar;"] = '\u{2226}',["NotElement;"] = '\u{2209}',["NotEqual;"] = '\u{2260}',["NotEqualTilde;"] = '\u{2242}\u{338}',
["NotExists;"] = '\u{2204}',["NotGreater;"] = '\u{226f}',["NotGreaterEqual;"] = '\u{2271}',["NotGreaterFullEqual;"] = '\u{2267}\u{338}',["NotGreaterGreater;"] = '\u{226b}\u{338}',
["NotGreaterLess;"] = '\u{2279}',["NotGreaterSlantEqual;"] = '\u{2a7e}\u{338}',["NotGreaterTilde;"] = '\u{2275}',["NotHumpDownHump;"] = '\u{224e}\u{338}',["NotHumpEqual;"] = '\u{224f}\u{338}',
["notin;"] = '\u{2209}',["notindot;"] = '\u{22f5}\u{338}',["notinE;"] = '\u{22f9}\u{338}',["notinva;"] = '\u{2209}',["notinvb;"] = '\u{22f7}',
["notinvc;"] = '\u{22f6}',["NotLeftTriangle;"] = '\u{22ea}',["NotLeftTriangleBar;"] = '\u{29cf}\u{338}',["NotLeftTriangleEqual;"] = '\u{22ec}',["NotLess;"] = '\u{226e}',
["NotLessEqual;"] = '\u{2270}',["NotLessGreater;"] = '\u{2278}',["NotLessLess;"] = '\u{226a}\u{338}',["NotLessSlantEqual;"] = '\u{2a7d}\u{338}',["NotLessTilde;"] = '\u{2274}',
["NotNestedGreaterGreater;"] = '\u{2aa2}\u{338}',["NotNestedLessLess;"] = '\u{2aa1}\u{338}',["notni;"] = '\u{220c}',["notniva;"] = '\u{220c}',["notnivb;"] = '\u{22fe}',
["notnivc;"] = '\u{22fd}',["NotPrecedes;"] = '\u{2280}',["NotPrecedesEqual;"] = '\u{2aaf}\u{338}',["NotPrecedesSlantEqual;"] = '\u{22e0}',["NotReverseElement;"] = '\u{220c}',
["NotRightTriangle;"] = '\u{22eb}',["NotRightTriangleBar;"] = '\u{29d0}\u{338}',["NotRightTriangleEqual;"] = '\u{22ed}',["NotSquareSubset;"] = '\u{228f}\u{338}',["NotSquareSubsetEqual;"] = '\u{22e2}',
["NotSquareSuperset;"] = '\u{2290}\u{338}',["NotSquareSupersetEqual;"] = '\u{22e3}',["NotSubset;"] = '\u{2282}\u{20d2}',["NotSubsetEqual;"] = '\u{2288}',["NotSucceeds;"] = '\u{2281}',
["NotSucceedsEqual;"] = '\u{2ab0}\u{338}',["NotSucceedsSlantEqual;"] = '\u{22e1}',["NotSucceedsTilde;"] = '\u{227f}\u{338}',["NotSuperset;"] = '\u{2283}\u{20d2}',["NotSupersetEqual;"] = '\u{2289}',
["NotTilde;"] = '\u{2241}',["NotTildeEqual;"] = '\u{2244}',["NotTildeFullEqual;"] = '\u{2247}',["NotTildeTilde;"] = '\u{2249}',["NotVerticalBar;"] = '\u{2224}',
["npar;"] = '\u{2226}',["nparallel;"] = '\u{2226}',["nparsl;"] = '\u{2afd}\u{20e5}',["npart;"] = '\u{2202}\u{338}',["npolint;"] = '\u{2a14}',
["npr;"] = '\u{2280}',["nprcue;"] = '\u{22e0}',["npre;"] = '\u{2aaf}\u{338}',["nprec;"] = '\u{2280}',["npreceq;"] = '\u{2aaf}\u{338}',
["nrArr;"] = '\u{21cf}',["nrarr;"] = '\u{219b}',["nrarrc;"] = '\u{2933}\u{338}',["nrarrw;"] = '\u{219d}\u{338}',["nRightarrow;"] = '\u{21cf}',
["nrightarrow;"] = '\u{219b}',["nrtri;"] = '\u{22eb}',["nrtrie;"] = '\u{22ed}',["nsc;"] = '\u{2281}',["nsccue;"] = '\u{22e1}',
["nsce;"] = '\u{2ab0}\u{338}',["Nscr;"] = '\u{1d4a9}',["nscr;"] = '\u{1d4c3}',["nshortmid;"] = '\u{2224}',["nshortparallel;"] = '\u{2226}',
["nsim;"] = '\u{2241}',["nsime;"] = '\u{2244}',["nsimeq;"] = '\u{2244}',["nsmid;"] = '\u{2224}',["nspar;"] = '\u{2226}',
["nsqsube;"] = '\u{22e2}',["nsqsupe;"] = '\u{22e3}',["nsub;"] = '\u{2284}',["nsubE;"] = '\u{2ac5}\u{338}',["nsube;"] = '\u{2288}',
["nsubset;"] = '\u{2282}\u{20d2}',["nsubseteq;"] = '\u{2288}',["nsubseteqq;"] = '\u{2ac5}\u{338}',["nsucc;"] = '\u{2281}',["nsucceq;"] = '\u{2ab0}\u{338}',
["nsup;"] = '\u{2285}',["nsupE;"] = '\u{2ac6}\u{338}',["nsupe;"] = '\u{2289}',["nsupset;"] = '\u{2283}\u{20d2}',["nsupseteq;"] = '\u{2289}',
["nsupseteqq;"] = '\u{2ac6}\u{338}',["ntgl;"] = '\u{2279}',["Ntilde"] = '\u{d1}',["ntilde"] = '\u{f1}',["Ntilde;"] = '\u{d1}',
["ntilde;"] = '\u{f1}',["ntlg;"] = '\u{2278}',["ntriangleleft;"] = '\u{22ea}',["ntrianglelefteq;"] = '\u{22ec}',["ntriangleright;"] = '\u{22eb}',
["ntrianglerighteq;"] = '\u{22ed}',["Nu;"] = '\u{39d}',["nu;"] = '\u{3bd}',["num;"] = '#',["numero;"] = '\u{2116}',
["numsp;"] = '\u{2007}',["nvap;"] = '\u{224d}\u{20d2}',["nVDash;"] = '\u{22af}',["nVdash;"] = '\u{22ae}',["nvDash;"] = '\u{22ad}',
["nvdash;"] = '\u{22ac}',["nvge;"] = '\u{2265}\u{20d2}',["nvgt;"] = '>\u{20d2}',["nvHarr;"] = '\u{2904}',["nvinfin;"] = '\u{29de}',
["nvlArr;"] = '\u{2902}',["nvle;"] = '\u{2264}\u{20d2}',["nvlt;"] = '<\u{20d2}',["nvltrie;"] = '\u{22b4}\u{20d2}',["nvrArr;"] = '\u{2903}',
["nvrtrie;"] = '\u{22b5}\u{20d2}',["nvsim;"] = '\u{223c}\u{20d2}',["nwarhk;"] = '\u{2923}',["nwArr;"] = '\u{21d6}',["nwarr;"] = '\u{2196}',
["nwarrow;"] = '\u{2196}',["nwnear;"] = '\u{2927}',["Oacute"] = '\u{d3}',["oacute"] = '\u{f3}',["Oacute;"] = '\u{d3}',
["oacute;"] = '\u{f3}',["oast;"] = '\u{229b}',["ocir;"] = '\u{229a}',["Ocirc"] = '\u{d4}',["ocirc"] = '\u{f4}',
["Ocirc;"] = '\u{d4}',["ocirc;"] = '\u{f4}',["Ocy;"] = '\u{41e}',["ocy;"] = '\u{43e}',["odash;"] = '\u{229d}',
["Odblac;"] = '\u{150}',["odblac;"] = '\u{151}',["odiv;"] = '\u{2a38}',["odot;"] = '\u{2299}',["odsold;"] = '\u{29bc}',
["OElig;"] = '\u{152}',["oelig;"] = '\u{153}',["ofcir;"] = '\u{29bf}',["Ofr;"] = '\u{1d512}',["ofr;"] = '\u{1d52c}',
["ogon;"] = '\u{2db}',["Ograve"] = '\u{d2}',["ograve"] = '\u{f2}',["Ograve;"] = '\u{d2}',["ograve;"] = '\u{f2}',
["ogt;"] = '\u{29c1}',["ohbar;"] = '\u{29b5}',["ohm;"] = '\u{3a9}',["oint;"] = '\u{222e}',["olarr;"] = '\u{21ba}',
["olcir;"] = '\u{29be}',["olcross;"] = '\u{29bb}',["oline;"] = '\u{203e}',["olt;"] = '\u{29c0}',["Omacr;"] = '\u{14c}',
["omacr;"] = '\u{14d}',["Omega;"] = '\u{3a9}',["omega;"] = '\u{3c9}',["Omicron;"] = '\u{39f}',["omicron;"] = '\u{3bf}',
["omid;"] = '\u{29b6}',["ominus;"] = '\u{2296}',["Oopf;"] = '\u{1d546}',["oopf;"] = '\u{1d560}',["opar;"] = '\u{29b7}',
["OpenCurlyDoubleQuote;"] = '\u{201c}',["OpenCurlyQuote;"] = '\u{2018}',["operp;"] = '\u{29b9}',["oplus;"] = '\u{2295}',["Or;"] = '\u{2a54}',
["or;"] = '\u{2228}',["orarr;"] = '\u{21bb}',["ord;"] = '\u{2a5d}',["order;"] = '\u{2134}',["orderof;"] = '\u{2134}',
["ordf"] = '\u{aa}',["ordf;"] = '\u{aa}',["ordm"] = '\u{ba}',["ordm;"] = '\u{ba}',["origof;"] = '\u{22b6}',
["oror;"] = '\u{2a56}',["orslope;"] = '\u{2a57}',["orv;"] = '\u{2a5b}',["oS;"] = '\u{24c8}',["Oscr;"] = '\u{1d4aa}',
["oscr;"] = '\u{2134}',["Oslash"] = '\u{d8}',["oslash"] = '\u{f8}',["Oslash;"] = '\u{d8}',["oslash;"] = '\u{f8}',
["osol;"] = '\u{2298}',["Otilde"] = '\u{d5}',["otilde"] = '\u{f5}',["Otilde;"] = '\u{d5}',["otilde;"] = '\u{f5}',
["Otimes;"] = '\u{2a37}',["otimes;"] = '\u{2297}',["otimesas;"] = '\u{2a36}',["Ouml"] = '\u{d6}',["ouml"] = '\u{f6}',
["Ouml;"] = '\u{d6}',["ouml;"] = '\u{f6}',["ovbar;"] = '\u{233d}',["OverBar;"] = '\u{203e}',["OverBrace;"] = '\u{23de}',
["OverBracket;"] = '\u{23b4}',["OverParenthesis;"] = '\u{23dc}',["par;"] = '\u{2225}',["para"] = '\u{b6}',["para;"] = '\u{b6}',
["parallel;"] = '\u{2225}',["parsim;"] = '\u{2af3}',["parsl;"] = '\u{2afd}',["part;"] = '\u{2202}',["PartialD;"] = '\u{2202}',
["Pcy;"] = '\u{41f}',["pcy;"] = '\u{43f}',["percnt;"] = '%',["period;"] = '.',["permil;"] = '\u{2030}',
["perp;"] = '\u{22a5}',["pertenk;"] = '\u{2031}',["Pfr;"] = '\u{1d513}',["pfr;"] = '\u{1d52d}',["Phi;"] = '\u{3a6}',
["phi;"] = '\u{3c6}',["phiv;"] = '\u{3d5}',["phmmat;"] = '\u{2133}',["phone;"] = '\u{260e}',["Pi;"] = '\u{3a0}',
["pi;"] = '\u{3c0}',["pitchfork;"] = '\u{22d4}',["piv;"] = '\u{3d6}',["planck;"] = '\u{210f}',["planckh;"] = '\u{210e}',
["plankv;"] = '\u{210f}',["plus;"] = '+',["plusacir;"] = '\u{2a23}',["plusb;"] = '\u{229e}',["pluscir;"] = '\u{2a22}',
["plusdo;"] = '\u{2214}',["plusdu;"] = '\u{2a25}',["pluse;"] = '\u{2a72}',["PlusMinus;"] = '\u{b1}',["plusmn"] = '\u{b1}',
["plusmn;"] = '\u{b1}',["plussim;"] = '\u{2a26}',["plustwo;"] = '\u{2a27}',["pm;"] = '\u{b1}',["Poincareplane;"] = '\u{210c}',
["pointint;"] = '\u{2a15}',["Popf;"] = '\u{2119}',["popf;"] = '\u{1d561}',["pound"] = '\u{a3}',["pound;"] = '\u{a3}',
["Pr;"] = '\u{2abb}',["pr;"] = '\u{227a}',["prap;"] = '\u{2ab7}',["prcue;"] = '\u{227c}',["prE;"] = '\u{2ab3}',
["pre;"] = '\u{2aaf}',["prec;"] = '\u{227a}',["precapprox;"] = '\u{2ab7}',["preccurlyeq;"] = '\u{227c}',["Precedes;"] = '\u{227a}',
["PrecedesEqual;"] = '\u{2aaf}',["PrecedesSlantEqual;"] = '\u{227c}',["PrecedesTilde;"] = '\u{227e}',["preceq;"] = '\u{2aaf}',["precnapprox;"] = '\u{2ab9}',
["precneqq;"] = '\u{2ab5}',["precnsim;"] = '\u{22e8}',["precsim;"] = '\u{227e}',["Prime;"] = '\u{2033}',["prime;"] = '\u{2032}',
["primes;"] = '\u{2119}',["prnap;"] = '\u{2ab9}',["prnE;"] = '\u{2ab5}',["prnsim;"] = '\u{22e8}',["prod;"] = '\u{220f}',
["Product;"] = '\u{220f}',["profalar;"] = '\u{232e}',["profline;"] = '\u{2312}',["profsurf;"] = '\u{2313}',["prop;"] = '\u{221d}',
["Proportion;"] = '\u{2237}',["Proportional;"] = '\u{221d}',["propto;"] = '\u{221d}',["prsim;"] = '\u{227e}',["prurel;"] = '\u{22b0}',
["Pscr;"] = '\u{1d4ab}',["pscr;"] = '\u{1d4c5}',["Psi;"] = '\u{3a8}',["psi;"] = '\u{3c8}',["puncsp;"] = '\u{2008}',
["Qfr;"] = '\u{1d514}',["qfr;"] = '\u{1d52e}',["qint;"] = '\u{2a0c}',["Qopf;"] = '\u{211a}',["qopf;"] = '\u{1d562}',
["qprime;"] = '\u{2057}',["Qscr;"] = '\u{1d4ac}',["qscr;"] = '\u{1d4c6}',["quaternions;"] = '\u{210d}',["quatint;"] = '\u{2a16}',
["quest;"] = '?',["questeq;"] = '\u{225f}',["QUOT"] = '"',["quot"] = '"',["QUOT;"] = '"',
["quot;"] = '"',["rAarr;"] = '\u{21db}',["race;"] = '\u{223d}\u{331}',["Racute;"] = '\u{154}',["racute;"] = '\u{155}',
["radic;"] = '\u{221a}',["raemptyv;"] = '\u{29b3}',["Rang;"] = '\u{27eb}',["rang;"] = '\u{27e9}',["rangd;"] = '\u{2992}',
["range;"] = '\u{29a5}',["rangle;"] = '\u{27e9}',["raquo"] = '\u{bb}',["raquo;"] = '\u{bb}',["Rarr;"] = '\u{21a0}',
["rArr;"] = '\u{21d2}',["rarr;"] = '\u{2192}',["rarrap;"] = '\u{2975}',["rarrb;"] = '\u{21e5}',["rarrbfs;"] = '\u{2920}',
["rarrc;"] = '\u{2933}',["rarrfs;"] = '\u{291e}',["rarrhk;"] = '\u{21aa}',["rarrlp;"] = '\u{21ac}',["rarrpl;"] = '\u{2945}',
["rarrsim;"] = '\u{2974}',["Rarrtl;"] = '\u{2916}',["rarrtl;"] = '\u{21a3}',["rarrw;"] = '\u{219d}',["rAtail;"] = '\u{291c}',
["ratail;"] = '\u{291a}',["ratio;"] = '\u{2236}',["rationals;"] = '\u{211a}',["RBarr;"] = '\u{2910}',["rBarr;"] = '\u{290f}',
["rbarr;"] = '\u{290d}',["rbbrk;"] = '\u{2773}',["rbrace;"] = '}',["rbrack;"] = ']',["rbrke;"] = '\u{298c}',
["rbrksld;"] = '\u{298e}',["rbrkslu;"] = '\u{2990}',["Rcaron;"] = '\u{158}',["rcaron;"] = '\u{159}',["Rcedil;"] = '\u{156}',
["rcedil;"] = '\u{157}',["rceil;"] = '\u{2309}',["rcub;"] = '}',["Rcy;"] = '\u{420}',["rcy;"] = '\u{440}',
["rdca;"] = '\u{2937}',["rdldhar;"] = '\u{2969}',["rdquo;"] = '\u{201d}',["rdquor;"] = '\u{201d}',["rdsh;"] = '\u{21b3}',
["Re;"] = '\u{211c}',["real;"] = '\u{211c}',["realine;"] = '\u{211b}',["realpart;"] = '\u{211c}',["reals;"] = '\u{211d}',
["rect;"] = '\u{25ad}',["REG"] = '\u{ae}',["reg"] = '\u{ae}',["REG;"] = '\u{ae}',["reg;"] = '\u{ae}',
["ReverseElement;"] = '\u{220b}',["ReverseEquilibrium;"] = '\u{21cb}',["ReverseUpEquilibrium;"] = '\u{296f}',["rfisht;"] = '\u{297d}',["rfloor;"] = '\u{230b}',
["Rfr;"] = '\u{211c}',["rfr;"] = '\u{1d52f}',["rHar;"] = '\u{2964}',["rhard;"] = '\u{21c1}',["rharu;"] = '\u{21c0}',
["rharul;"] = '\u{296c}',["Rho;"] = '\u{3a1}',["rho;"] = '\u{3c1}',["rhov;"] = '\u{3f1}',["RightAngleBracket;"] = '\u{27e9}',
["RightArrow;"] = '\u{2192}',["Rightarrow;"] = '\u{21d2}',["rightarrow;"] = '\u{2192}',["RightArrowBar;"] = '\u{21e5}',["RightArrowLeftArrow;"] = '\u{21c4}',
["rightarrowtail;"] = '\u{21a3}',["RightCeiling;"] = '\u{2309}',["RightDoubleBracket;"] = '\u{27e7}',["RightDownTeeVector;"] = '\u{295d}',["RightDownVector;"] = '\u{21c2}',
["RightDownVectorBar;"] = '\u{2955}',["RightFloor;"] = '\u{230b}',["rightharpoondown;"] = '\u{21c1}',["rightharpoonup;"] = '\u{21c0}',["rightleftarrows;"] = '\u{21c4}',
["rightleftharpoons;"] = '\u{21cc}',["rightrightarrows;"] = '\u{21c9}',["rightsquigarrow;"] = '\u{219d}',["RightTee;"] = '\u{22a2}',["RightTeeArrow;"] = '\u{21a6}',
["RightTeeVector;"] = '\u{295b}',["rightthreetimes;"] = '\u{22cc}',["RightTriangle;"] = '\u{22b3}',["RightTriangleBar;"] = '\u{29d0}',["RightTriangleEqual;"] = '\u{22b5}',
["RightUpDownVector;"] = '\u{294f}',["RightUpTeeVector;"] = '\u{295c}',["RightUpVector;"] = '\u{21be}',["RightUpVectorBar;"] = '\u{2954}',["RightVector;"] = '\u{21c0}',
["RightVectorBar;"] = '\u{2953}',["ring;"] = '\u{2da}',["risingdotseq;"] = '\u{2253}',["rlarr;"] = '\u{21c4}',["rlhar;"] = '\u{21cc}',
["rlm;"] = '\u{200f}',["rmoust;"] = '\u{23b1}',["rmoustache;"] = '\u{23b1}',["rnmid;"] = '\u{2aee}',["roang;"] = '\u{27ed}',
["roarr;"] = '\u{21fe}',["robrk;"] = '\u{27e7}',["ropar;"] = '\u{2986}',["Ropf;"] = '\u{211d}',["ropf;"] = '\u{1d563}',
["roplus;"] = '\u{2a2e}',["rotimes;"] = '\u{2a35}',["RoundImplies;"] = '\u{2970}',["rpar;"] = ')',["rpargt;"] = '\u{2994}',
["rppolint;"] = '\u{2a12}',["rrarr;"] = '\u{21c9}',["Rrightarrow;"] = '\u{21db}',["rsaquo;"] = '\u{203a}',["Rscr;"] = '\u{211b}',
["rscr;"] = '\u{1d4c7}',["Rsh;"] = '\u{21b1}',["rsh;"] = '\u{21b1}',["rsqb;"] = ']',["rsquo;"] = '\u{2019}',
["rsquor;"] = '\u{2019}',["rthree;"] = '\u{22cc}',["rtimes;"] = '\u{22ca}',["rtri;"] = '\u{25b9}',["rtrie;"] = '\u{22b5}',
["rtrif;"] = '\u{25b8}',["rtriltri;"] = '\u{29ce}',["RuleDelayed;"] = '\u{29f4}',["ruluhar;"] = '\u{2968}',["rx;"] = '\u{211e}',
["Sacute;"] = '\u{15a}',["sacute;"] = '\u{15b}',["sbquo;"] = '\u{201a}',["Sc;"] = '\u{2abc}',["sc;"] = '\u{227b}',
["scap;"] = '\u{2ab8}',["Scaron;"] = '\u{160}',["scaron;"] = '\u{161}',["sccue;"] = '\u{227d}',["scE;"] = '\u{2ab4}',
["sce;"] = '\u{2ab0}',["Scedil;"] = '\u{15e}',["scedil;"] = '\u{15f}',["Scirc;"] = '\u{15c}',["scirc;"] = '\u{15d}',
["scnap;"] = '\u{2aba}',["scnE;"] = '\u{2ab6}',["scnsim;"] = '\u{22e9}',["scpolint;"] = '\u{2a13}',["scsim;"] = '\u{227f}',
["Scy;"] = '\u{421}',["scy;"] = '\u{441}',["sdot;"] = '\u{22c5}',["sdotb;"] = '\u{22a1}',["sdote;"] = '\u{2a66}',
["searhk;"] = '\u{2925}',["seArr;"] = '\u{21d8}',["searr;"] = '\u{2198}',["searrow;"] = '\u{2198}',["sect"] = '\u{a7}',
["sect;"] = '\u{a7}',["semi;"] = ';',["seswar;"] = '\u{2929}',["setminus;"] = '\u{2216}',["setmn;"] = '\u{2216}',
["sext;"] = '\u{2736}',["Sfr;"] = '\u{1d516}',["sfr;"] = '\u{1d530}',["sfrown;"] = '\u{2322}',["sharp;"] = '\u{266f}',
["SHCHcy;"] = '\u{429}',["shchcy;"] = '\u{449}',["SHcy;"] = '\u{428}',["shcy;"] = '\u{448}',["ShortDownArrow;"] = '\u{2193}',
["ShortLeftArrow;"] = '\u{2190}',["shortmid;"] = '\u{2223}',["shortparallel;"] = '\u{2225}',["ShortRightArrow;"] = '\u{2192}',["ShortUpArrow;"] = '\u{2191}',
["shy"] = '\u{ad}',["shy;"] = '\u{ad}',["Sigma;"] = '\u{3a3}',["sigma;"] = '\u{3c3}',["sigmaf;"] = '\u{3c2}',
["sigmav;"] = '\u{3c2}',["sim;"] = '\u{223c}',["simdot;"] = '\u{2a6a}',["sime;"] = '\u{2243}',["simeq;"] = '\u{2243}',
["simg;"] = '\u{2a9e}',["simgE;"] = '\u{2aa0}',["siml;"] = '\u{2a9d}',["simlE;"] = '\u{2a9f}',["simne;"] = '\u{2246}',
["simplus;"] = '\u{2a24}',["simrarr;"] = '\u{2972}',["slarr;"] = '\u{2190}',["SmallCircle;"] = '\u{2218}',["smallsetminus;"] = '\u{2216}',
["smashp;"] = '\u{2a33}',["smeparsl;"] = '\u{29e4}',["smid;"] = '\u{2223}',["smile;"] = '\u{2323}',["smt;"] = '\u{2aaa}',
["smte;"] = '\u{2aac}',["smtes;"] = '\u{2aac}\u{fe00}',["SOFTcy;"] = '\u{42c}',["softcy;"] = '\u{44c}',["sol;"] = '/',
["solb;"] = '\u{29c4}',["solbar;"] = '\u{233f}',["Sopf;"] = '\u{1d54a}',["sopf;"] = '\u{1d564}',["spades;"] = '\u{2660}',
["spadesuit;"] = '\u{2660}',["spar;"] = '\u{2225}',["sqcap;"] = '\u{2293}',["sqcaps;"] = '\u{2293}\u{fe00}',["sqcup;"] = '\u{2294}',
["sqcups;"] = '\u{2294}\u{fe00}',["Sqrt;"] = '\u{221a}',["sqsub;"] = '\u{228f}',["sqsube;"] = '\u{2291}',["sqsubset;"] = '\u{228f}',
["sqsubseteq;"] = '\u{2291}',["sqsup;"] = '\u{2290}',["sqsupe;"] = '\u{2292}',["sqsupset;"] = '\u{2290}',["sqsupseteq;"] = '\u{2292}',
["squ;"] = '\u{25a1}',["Square;"] = '\u{25a1}',["square;"] = '\u{25a1}',["SquareIntersection;"] = '\u{2293}',["SquareSubset;"] = '\u{228f}',
["SquareSubsetEqual;"] = '\u{2291}',["SquareSuperset;"] = '\u{2290}',["SquareSupersetEqual;"] = '\u{2292}',["SquareUnion;"] = '\u{2294}',["squarf;"] = '\u{25aa}',
["squf;"] = '\u{25aa}',["srarr;"] = '\u{2192}',["Sscr;"] = '\u{1d4ae}',["sscr;"] = '\u{1d4c8}',["ssetmn;"] = '\u{2216}',
["ssmile;"] = '\u{2323}',["sstarf;"] = '\u{22c6}',["Star;"] = '\u{22c6}',["star;"] = '\u{2606}',["starf;"] = '\u{2605}',
["straightepsilon;"] = '\u{3f5}',["straightphi;"] = '\u{3d5}',["strns;"] = '\u{af}',["Sub;"] = '\u{22d0}',["sub;"] = '\u{2282}',
["subdot;"] = '\u{2abd}',["subE;"] = '\u{2ac5}',["sube;"] = '\u{2286}',["subedot;"] = '\u{2ac3}',["submult;"] = '\u{2ac1}',
["subnE;"] = '\u{2acb}',["subne;"] = '\u{228a}',["subplus;"] = '\u{2abf}',["subrarr;"] = '\u{2979}',["Subset;"] = '\u{22d0}',
["subset;"] = '\u{2282}',["subseteq;"] = '\u{2286}',["subseteqq;"] = '\u{2ac5}',["SubsetEqual;"] = '\u{2286}',["subsetneq;"] = '\u{228a}',
["subsetneqq;"] = '\u{2acb}',["subsim;"] = '\u{2ac7}',["subsub;"] = '\u{2ad5}',["subsup;"] = '\u{2ad3}',["succ;"] = '\u{227b}',
["succapprox;"] = '\u{2ab8}',["succcurlyeq;"] = '\u{227d}',["Succeeds;"] = '\u{227b}',["SucceedsEqual;"] = '\u{2ab0}',["SucceedsSlantEqual;"] = '\u{227d}',
["SucceedsTilde;"] = '\u{227f}',["succeq;"] = '\u{2ab0}',["succnapprox;"] = '\u{2aba}',["succneqq;"] = '\u{2ab6}',["succnsim;"] = '\u{22e9}',
["succsim;"] = '\u{227f}',["SuchThat;"] = '\u{220b}',["Sum;"] = '\u{2211}',["sum;"] = '\u{2211}',["sung;"] = '\u{266a}',
["sup1"] = '\u{b9}',["sup1;"] = '\u{b9}',["sup2"] = '\u{b2}',["sup2;"] = '\u{b2}',["sup3"] = '\u{b3}',
["sup3;"] = '\u{b3}',["Sup;"] = '\u{22d1}',["sup;"] = '\u{2283}',["supdot;"] = '\u{2abe}',["supdsub;"] = '\u{2ad8}',
["supE;"] = '\u{2ac6}',["supe;"] = '\u{2287}',["supedot;"] = '\u{2ac4}',["Superset;"] = '\u{2283}',["SupersetEqual;"] = '\u{2287}',
["suphsol;"] = '\u{27c9}',["suphsub;"] = '\u{2ad7}',["suplarr;"] = '\u{297b}',["supmult;"] = '\u{2ac2}',["supnE;"] = '\u{2acc}',
["supne;"] = '\u{228b}',["supplus;"] = '\u{2ac0}',["Supset;"] = '\u{22d1}',["supset;"] = '\u{2283}',["supseteq;"] = '\u{2287}',
["supseteqq;"] = '\u{2ac6}',["supsetneq;"] = '\u{228b}',["supsetneqq;"] = '\u{2acc}',["supsim;"] = '\u{2ac8}',["supsub;"] = '\u{2ad4}',
["supsup;"] = '\u{2ad6}',["swarhk;"] = '\u{2926}',["swArr;"] = '\u{21d9}',["swarr;"] = '\u{2199}',["swarrow;"] = '\u{2199}',
["swnwar;"] = '\u{292a}',["szlig"] = '\u{df}',["szlig;"] = '\u{df}',["Tab;"] = '',["target;"] = '\u{2316}',
["Tau;"] = '\u{3a4}',["tau;"] = '\u{3c4}',["tbrk;"] = '\u{23b4}',["Tcaron;"] = '\u{164}',["tcaron;"] = '\u{165}',
["Tcedil;"] = '\u{162}',["tcedil;"] = '\u{163}',["Tcy;"] = '\u{422}',["tcy;"] = '\u{442}',["tdot;"] = '\u{20db}',
["telrec;"] = '\u{2315}',["Tfr;"] = '\u{1d517}',["tfr;"] = '\u{1d531}',["there4;"] = '\u{2234}',["Therefore;"] = '\u{2234}',
["therefore;"] = '\u{2234}',["Theta;"] = '\u{398}',["theta;"] = '\u{3b8}',["thetasym;"] = '\u{3d1}',["thetav;"] = '\u{3d1}',
["thickapprox;"] = '\u{2248}',["thicksim;"] = '\u{223c}',["ThickSpace;"] = '\u{205f}\u{200a}',["thinsp;"] = '\u{2009}',["ThinSpace;"] = '\u{2009}',
["thkap;"] = '\u{2248}',["thksim;"] = '\u{223c}',["THORN"] = '\u{de}',["thorn"] = '\u{fe}',["THORN;"] = '\u{de}',
["thorn;"] = '\u{fe}',["Tilde;"] = '\u{223c}',["tilde;"] = '\u{2dc}',["TildeEqual;"] = '\u{2243}',["TildeFullEqual;"] = '\u{2245}',
["TildeTilde;"] = '\u{2248}',["times"] = '\u{d7}',["times;"] = '\u{d7}',["timesb;"] = '\u{22a0}',["timesbar;"] = '\u{2a31}',
["timesd;"] = '\u{2a30}',["tint;"] = '\u{222d}',["toea;"] = '\u{2928}',["top;"] = '\u{22a4}',["topbot;"] = '\u{2336}',
["topcir;"] = '\u{2af1}',["Topf;"] = '\u{1d54b}',["topf;"] = '\u{1d565}',["topfork;"] = '\u{2ada}',["tosa;"] = '\u{2929}',
["tprime;"] = '\u{2034}',["TRADE;"] = '\u{2122}',["trade;"] = '\u{2122}',["triangle;"] = '\u{25b5}',["triangledown;"] = '\u{25bf}',
["triangleleft;"] = '\u{25c3}',["trianglelefteq;"] = '\u{22b4}',["triangleq;"] = '\u{225c}',["triangleright;"] = '\u{25b9}',["trianglerighteq;"] = '\u{22b5}',
["tridot;"] = '\u{25ec}',["trie;"] = '\u{225c}',["triminus;"] = '\u{2a3a}',["TripleDot;"] = '\u{20db}',["triplus;"] = '\u{2a39}',
["trisb;"] = '\u{29cd}',["tritime;"] = '\u{2a3b}',["trpezium;"] = '\u{23e2}',["Tscr;"] = '\u{1d4af}',["tscr;"] = '\u{1d4c9}',
["TScy;"] = '\u{426}',["tscy;"] = '\u{446}',["TSHcy;"] = '\u{40b}',["tshcy;"] = '\u{45b}',["Tstrok;"] = '\u{166}',
["tstrok;"] = '\u{167}',["twixt;"] = '\u{226c}',["twoheadleftarrow;"] = '\u{219e}',["twoheadrightarrow;"] = '\u{21a0}',["Uacute"] = '\u{da}',
["uacute"] = '\u{fa}',["Uacute;"] = '\u{da}',["uacute;"] = '\u{fa}',["Uarr;"] = '\u{219f}',["uArr;"] = '\u{21d1}',
["uarr;"] = '\u{2191}',["Uarrocir;"] = '\u{2949}',["Ubrcy;"] = '\u{40e}',["ubrcy;"] = '\u{45e}',["Ubreve;"] = '\u{16c}',
["ubreve;"] = '\u{16d}',["Ucirc"] = '\u{db}',["ucirc"] = '\u{fb}',["Ucirc;"] = '\u{db}',["ucirc;"] = '\u{fb}',
["Ucy;"] = '\u{423}',["ucy;"] = '\u{443}',["udarr;"] = '\u{21c5}',["Udblac;"] = '\u{170}',["udblac;"] = '\u{171}',
["udhar;"] = '\u{296e}',["ufisht;"] = '\u{297e}',["Ufr;"] = '\u{1d518}',["ufr;"] = '\u{1d532}',["Ugrave"] = '\u{d9}',
["ugrave"] = '\u{f9}',["Ugrave;"] = '\u{d9}',["ugrave;"] = '\u{f9}',["uHar;"] = '\u{2963}',["uharl;"] = '\u{21bf}',
["uharr;"] = '\u{21be}',["uhblk;"] = '\u{2580}',["ulcorn;"] = '\u{231c}',["ulcorner;"] = '\u{231c}',["ulcrop;"] = '\u{230f}',
["ultri;"] = '\u{25f8}',["Umacr;"] = '\u{16a}',["umacr;"] = '\u{16b}',["uml"] = '\u{a8}',["uml;"] = '\u{a8}',
["UnderBar;"] = '_',["UnderBrace;"] = '\u{23df}',["UnderBracket;"] = '\u{23b5}',["UnderParenthesis;"] = '\u{23dd}',["Union;"] = '\u{22c3}',
["UnionPlus;"] = '\u{228e}',["Uogon;"] = '\u{172}',["uogon;"] = '\u{173}',["Uopf;"] = '\u{1d54c}',["uopf;"] = '\u{1d566}',
["UpArrow;"] = '\u{2191}',["Uparrow;"] = '\u{21d1}',["uparrow;"] = '\u{2191}',["UpArrowBar;"] = '\u{2912}',["UpArrowDownArrow;"] = '\u{21c5}',
["UpDownArrow;"] = '\u{2195}',["Updownarrow;"] = '\u{21d5}',["updownarrow;"] = '\u{2195}',["UpEquilibrium;"] = '\u{296e}',["upharpoonleft;"] = '\u{21bf}',
["upharpoonright;"] = '\u{21be}',["uplus;"] = '\u{228e}',["UpperLeftArrow;"] = '\u{2196}',["UpperRightArrow;"] = '\u{2197}',["Upsi;"] = '\u{3d2}',
["upsi;"] = '\u{3c5}',["upsih;"] = '\u{3d2}',["Upsilon;"] = '\u{3a5}',["upsilon;"] = '\u{3c5}',["UpTee;"] = '\u{22a5}',
["UpTeeArrow;"] = '\u{21a5}',["upuparrows;"] = '\u{21c8}',["urcorn;"] = '\u{231d}',["urcorner;"] = '\u{231d}',["urcrop;"] = '\u{230e}',
["Uring;"] = '\u{16e}',["uring;"] = '\u{16f}',["urtri;"] = '\u{25f9}',["Uscr;"] = '\u{1d4b0}',["uscr;"] = '\u{1d4ca}',
["utdot;"] = '\u{22f0}',["Utilde;"] = '\u{168}',["utilde;"] = '\u{169}',["utri;"] = '\u{25b5}',["utrif;"] = '\u{25b4}',
["uuarr;"] = '\u{21c8}',["Uuml"] = '\u{dc}',["uuml"] = '\u{fc}',["Uuml;"] = '\u{dc}',["uuml;"] = '\u{fc}',
["uwangle;"] = '\u{29a7}',["vangrt;"] = '\u{299c}',["varepsilon;"] = '\u{3f5}',["varkappa;"] = '\u{3f0}',["varnothing;"] = '\u{2205}',
["varphi;"] = '\u{3d5}',["varpi;"] = '\u{3d6}',["varpropto;"] = '\u{221d}',["vArr;"] = '\u{21d5}',["varr;"] = '\u{2195}',
["varrho;"] = '\u{3f1}',["varsigma;"] = '\u{3c2}',["varsubsetneq;"] = '\u{228a}\u{fe00}',["varsubsetneqq;"] = '\u{2acb}\u{fe00}',["varsupsetneq;"] = '\u{228b}\u{fe00}',
["varsupsetneqq;"] = '\u{2acc}\u{fe00}',["vartheta;"] = '\u{3d1}',["vartriangleleft;"] = '\u{22b2}',["vartriangleright;"] = '\u{22b3}',["Vbar;"] = '\u{2aeb}',
["vBar;"] = '\u{2ae8}',["vBarv;"] = '\u{2ae9}',["Vcy;"] = '\u{412}',["vcy;"] = '\u{432}',["VDash;"] = '\u{22ab}',
["Vdash;"] = '\u{22a9}',["vDash;"] = '\u{22a8}',["vdash;"] = '\u{22a2}',["Vdashl;"] = '\u{2ae6}',["Vee;"] = '\u{22c1}',
["vee;"] = '\u{2228}',["veebar;"] = '\u{22bb}',["veeeq;"] = '\u{225a}',["vellip;"] = '\u{22ee}',["Verbar;"] = '\u{2016}',
["verbar;"] = '|',["Vert;"] = '\u{2016}',["vert;"] = '|',["VerticalBar;"] = '\u{2223}',["VerticalLine;"] = '|',
["VerticalSeparator;"] = '\u{2758}',["VerticalTilde;"] = '\u{2240}',["VeryThinSpace;"] = '\u{200a}',["Vfr;"] = '\u{1d519}',["vfr;"] = '\u{1d533}',
["vltri;"] = '\u{22b2}',["vnsub;"] = '\u{2282}\u{20d2}',["vnsup;"] = '\u{2283}\u{20d2}',["Vopf;"] = '\u{1d54d}',["vopf;"] = '\u{1d567}',
["vprop;"] = '\u{221d}',["vrtri;"] = '\u{22b3}',["Vscr;"] = '\u{1d4b1}',["vscr;"] = '\u{1d4cb}',["vsubnE;"] = '\u{2acb}\u{fe00}',
["vsubne;"] = '\u{228a}\u{fe00}',["vsupnE;"] = '\u{2acc}\u{fe00}',["vsupne;"] = '\u{228b}\u{fe00}',["Vvdash;"] = '\u{22aa}',["vzigzag;"] = '\u{299a}',
["Wcirc;"] = '\u{174}',["wcirc;"] = '\u{175}',["wedbar;"] = '\u{2a5f}',["Wedge;"] = '\u{22c0}',["wedge;"] = '\u{2227}',
["wedgeq;"] = '\u{2259}',["weierp;"] = '\u{2118}',["Wfr;"] = '\u{1d51a}',["wfr;"] = '\u{1d534}',["Wopf;"] = '\u{1d54e}',
["wopf;"] = '\u{1d568}',["wp;"] = '\u{2118}',["wr;"] = '\u{2240}',["wreath;"] = '\u{2240}',["Wscr;"] = '\u{1d4b2}',
["wscr;"] = '\u{1d4cc}',["xcap;"] = '\u{22c2}',["xcirc;"] = '\u{25ef}',["xcup;"] = '\u{22c3}',["xdtri;"] = '\u{25bd}',
["Xfr;"] = '\u{1d51b}',["xfr;"] = '\u{1d535}',["xhArr;"] = '\u{27fa}',["xharr;"] = '\u{27f7}',["Xi;"] = '\u{39e}',
["xi;"] = '\u{3be}',["xlArr;"] = '\u{27f8}',["xlarr;"] = '\u{27f5}',["xmap;"] = '\u{27fc}',["xnis;"] = '\u{22fb}',
["xodot;"] = '\u{2a00}',["Xopf;"] = '\u{1d54f}',["xopf;"] = '\u{1d569}',["xoplus;"] = '\u{2a01}',["xotime;"] = '\u{2a02}',
["xrArr;"] = '\u{27f9}',["xrarr;"] = '\u{27f6}',["Xscr;"] = '\u{1d4b3}',["xscr;"] = '\u{1d4cd}',["xsqcup;"] = '\u{2a06}',
["xuplus;"] = '\u{2a04}',["xutri;"] = '\u{25b3}',["xvee;"] = '\u{22c1}',["xwedge;"] = '\u{22c0}',["Yacute"] = '\u{dd}',
["yacute"] = '\u{fd}',["Yacute;"] = '\u{dd}',["yacute;"] = '\u{fd}',["YAcy;"] = '\u{42f}',["yacy;"] = '\u{44f}',
["Ycirc;"] = '\u{176}',["ycirc;"] = '\u{177}',["Ycy;"] = '\u{42b}',["ycy;"] = '\u{44b}',["yen"] = '\u{a5}',
["yen;"] = '\u{a5}',["Yfr;"] = '\u{1d51c}',["yfr;"] = '\u{1d536}',["YIcy;"] = '\u{407}',["yicy;"] = '\u{457}',
["Yopf;"] = '\u{1d550}',["yopf;"] = '\u{1d56a}',["Yscr;"] = '\u{1d4b4}',["yscr;"] = '\u{1d4ce}',["YUcy;"] = '\u{42e}',
["yucy;"] = '\u{44e}',["yuml"] = '\u{ff}',["Yuml;"] = '\u{178}',["yuml;"] = '\u{ff}',["Zacute;"] = '\u{179}',
["zacute;"] = '\u{17a}',["Zcaron;"] = '\u{17d}',["zcaron;"] = '\u{17e}',["Zcy;"] = '\u{417}',["zcy;"] = '\u{437}',
["Zdot;"] = '\u{17b}',["zdot;"] = '\u{17c}',["zeetrf;"] = '\u{2128}',["ZeroWidthSpace;"] = '\u{200b}',["Zeta;"] = '\u{396}',
["zeta;"] = '\u{3b6}',["Zfr;"] = '\u{2128}',["zfr;"] = '\u{1d537}',["ZHcy;"] = '\u{416}',["zhcy;"] = '\u{436}',
["zigrarr;"] = '\u{21dd}',["Zopf;"] = '\u{2124}',["zopf;"] = '\u{1d56b}',["Zscr;"] = '\u{1d4b5}',["zscr;"] = '\u{1d4cf}',
["zwj;"] = '\u{200d}',["zwnj;"] = '\u{200c}'
}


-- 左移运算
function html_parser.shift_right(value, n)
    return math.floor(value / 2^n)
  end

-- unicode转utf8 解决lua 默认chr 函数不支持unicode
function html_parser.unicode_to_utf8(hex,type)
    local codepoint = tonumber(hex, type)
    if codepoint and codepoint <= 0x7F then
    return string.char(codepoint)
    elseif codepoint <= 0x7FF then
    return string.char(192 + html_parser.shift_right(codepoint, 6), 128 + codepoint % 64)
    elseif codepoint <= 0xFFFF then
    return string.char(224 + html_parser.shift_right(codepoint, 12), 128 + html_parser.shift_right(codepoint, 6) % 64, 128 + codepoint % 64)
    elseif codepoint <= 0x10FFFF then
    return string.char(240 + html_parser.shift_right(codepoint, 18), 128 + html_parser.shift_right(codepoint, 12) % 64, 128 + html_parser.shift_right(codepoint, 6) % 64, 128 + codepoint % 64)
    end
    return ""
end

-- 替换的主体函数、跟_replace_charref 多了一个unicode转utf8的功能
function html_parser._replace_charref(s_body)
    if s_body[1]==nil or s_body[0]==nil then 
        return ""
    end 
    -- 判断s_body[0] 的第一位是否为\
    if string.sub(s_body[0],1,1)=="\\" then 
        s_body=s_body[0]
    else
        s_body=s_body[1]
    end
    if string.sub(s_body,1,1)=="#" then 
        --判断第二位是否为数字
        local num=0
        if string.sub(s_body,2,2)=="x" or string.sub(s_body,2,2)=="X" then 
            local s_tmp = string.sub(s_body, 3)       -- 获取子字符串
            s_tmp = string.gsub(s_tmp, ";*$", "")       -- 移除尾部的分号
            num = tonumber(s_tmp, 16)                 -- 从16进制转为整数
        else 
            local s_tmp = string.sub(s_body, 2)                           -- 获取子字符串
            s_tmp = string.gsub(s_tmp, ";*$", "")                  -- 移除尾部的分号
            num = tonumber(s_tmp,10)                    -- 从16进制转为整数
        end 
        if _invalid_charrefs[num] then 
            return _invalid_charrefs[num]
        end
        if num>=0xD800 and num<=0xDFFF or num>0x10FFFF then 
            return '\u{FFFD}'
        end
        if _invalid_codepoints[num] then 
            return ' '
        end
        --返回对应的字符
        return html_parser.unicode_to_utf8(num,10)
    -- 第一位为\ 第二位u
    elseif string.sub(s_body,1,1)=="\\" and  string.sub(s_body,2,2)=="u" then 
        local s_tmp = string.sub(s_body, 3)       -- 获取子字符串
        s_tmp = string.gsub(s_tmp, ";*$", "")       -- 移除尾部的分号
        --返回对应的字符
        return html_parser.unicode_to_utf8(s_tmp,16)
    else 
        if html5[s_body] then 
            return html5[s_body]
        end
        local x
        for x = #s_body, 2, -1 do
            local prefix = s_body:sub(1, x)
            if html5[prefix] then
                return html5[prefix] .. s_body:sub(x + 1)
            end
        end
        return '&' .. s_body
    end
end


function html_parser.unescape(str)
    if not str then
        return ""
    end
    local count=0
    while count<10 do
        count=count+1
        str=ngx.unescape_uri(str)
        if (ngx.re.find(str, "&|\\\\u[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]") == nil) then
            return string.lower(str)
        end
        local pattern = '&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)|\\\\u[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]'
        str=ngx.re.gsub(str,pattern, html_parser._replace_charref, "ijo")
    end
    return string.lower(str)
    
end

return html_parser

