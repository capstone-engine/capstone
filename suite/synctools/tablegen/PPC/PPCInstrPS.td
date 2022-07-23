def HasPS : Predicate<"PPCSubTarget->hasPS()">;
let Predicates = [HasPS] in {
let DecoderNamespace = "PS" in {

def PSQ_L    : PSForm_qd<56,
               (outs f8rc:$FRT), (ins memrid12:$src, u1imm:$W, u3imm: $I),
               "psq_l $FRT, $src, $W, $I", IIC_FPGeneral>;
def PSQ_LU   : PSForm_qd<57,
               (outs f8rc:$FRT), (ins memrid12:$src, u1imm:$W, u3imm: $I),
               "psq_lu $FRT, $src, $W, $I", IIC_FPGeneral>;
def PSQ_ST   : PSForm_qd<60,
               (outs), (ins f8rc:$FRT, memrid12:$dst, u1imm:$W, u3imm: $I),
               "psq_st $FRT, $dst, $W, $I", IIC_FPGeneral>;
def PSQ_STU  : PSForm_qd<61,
               (outs), (ins f8rc:$FRT, memrid12:$dst, u1imm:$W, u3imm: $I),
               "psq_stu $FRT, $dst, $W, $I", IIC_FPGeneral>;

def PSQ_LX   : PSForm_qi<6,
               (outs f8rc:$FRT), (ins gprc:$rA, gprc:$rB, u1imm:$W, u3imm: $I),
               "psq_lx $FRT, $rA, $rB, $W, $I", IIC_FPGeneral>;
def PSQ_STX  : PSForm_qi<7,
               (outs), (ins f8rc:$FRT,gprc:$rA, gprc:$rB, u1imm:$W, u3imm: $I),
               "psq_stx $FRT, $rA, $rB, $W, $I", IIC_FPGeneral>;
def PSQ_LUX  : PSForm_qi<38,
               (outs f8rc:$FRT), (ins gprc:$rA, gprc:$rB, u1imm:$W, u3imm: $I),
               "psq_lux $FRT, $rA, $rB, $W, $I", IIC_FPGeneral>;
def PSQ_STUX : PSForm_qi<39,
               (outs), (ins f8rc:$FRT,gprc:$rA, gprc:$rB, u1imm:$W, u3imm: $I),
               "psq_stux $FRT, $rA, $rB, $W, $I", IIC_FPGeneral>;

// op. FRT, FRA, FRC, FRB
multiclass PSForm_xr<bits<5> psxop, dag OOL, dag IOL, string asmbase,
                     string asmstr, InstrItinClass itin> {
  let BaseName = asmbase in {
    def NAME : PSForm_x<psxop, OOL, IOL,
                        !strconcat(asmbase, !strconcat(" ", asmstr)), itin>;
    let Defs = [CR1] in
    def o    : PSForm_x<psxop, OOL, IOL,
                        !strconcat(asmbase, !strconcat(". ", asmstr)), itin>,
                        isDOT;
  }
}

// op FRT, FRA, FRB
class PSForm_x1<bits<5> psxop, dag OOL, dag IOL, string asmstr,
                 InstrItinClass itin>
    : PSForm_x<psxop, OOL, IOL, asmstr, itin> {
  let FRC = 0;
}

// op. FRT, FRA, FRB
multiclass PSForm_x1r<bits<5> psxop, dag OOL, dag IOL, string asmbase,
                      string asmstr, InstrItinClass itin> {
  let BaseName = asmbase in {
    def NAME : PSForm_x1<psxop, OOL, IOL,
                         !strconcat(asmbase, !strconcat(" ", asmstr)), itin>;
    let Defs = [CR1] in
    def o    : PSForm_x1<psxop, OOL, IOL,
                         !strconcat(asmbase, !strconcat(". ", asmstr)), itin>,
                         isDOT;
  }
}

// op FRT, FRB
class PSForm_x2<bits<5> psxop, dag OOL, dag IOL, string asmstr,
                 InstrItinClass itin>
    : PSForm_x<psxop, OOL, IOL, asmstr, itin> {
  let FRA = 0;
  let FRC = 0;
}

// op. FRT, FRB
multiclass PSForm_x2r<bits<5> psxop, dag OOL, dag IOL, string asmbase,
                      string asmstr, InstrItinClass itin> {
  let BaseName = asmbase in {
    def NAME : PSForm_x2<psxop, OOL, IOL,
                         !strconcat(asmbase, !strconcat(" ", asmstr)), itin>;
    let Defs = [CR1] in
    def o    : PSForm_x2<psxop, OOL, IOL,
                         !strconcat(asmbase, !strconcat(". ", asmstr)), itin>,
                         isDOT;
  }
}

// op FRT, FRA, FRC
class PSForm_x3<bits<5> psxop, dag OOL, dag IOL, string asmstr,
                 InstrItinClass itin>
    : PSForm_x<psxop, OOL, IOL, asmstr, itin> {
  let FRB = 0;
}

// op. FRT, FRA, FRC
multiclass PSForm_x3r<bits<5> psxop, dag OOL, dag IOL, string asmbase,
                      string asmstr, InstrItinClass itin> {
  let BaseName = asmbase in {
    def NAME : PSForm_x3<psxop, OOL, IOL,
                         !strconcat(asmbase, !strconcat(" ", asmstr)), itin>;
    let Defs = [CR1] in
    def o    : PSForm_x3<psxop, OOL, IOL,
                         !strconcat(asmbase, !strconcat(". ", asmstr)), itin>,
                         isDOT;
  }
}

// op. FRT, FRA, FRB
multiclass PSForm_yr<bits<10> psyop, dag OOL, dag IOL, string asmbase,
                     string asmstr, InstrItinClass itin> {
  let BaseName = asmbase in {
    def NAME : PSForm_y<psyop, OOL, IOL,
                        !strconcat(asmbase, !strconcat(" ", asmstr)), itin>;
    let Defs = [CR1] in
    def o    : PSForm_y<psyop, OOL, IOL,
                        !strconcat(asmbase, !strconcat(". ", asmstr)), itin>,
                        isDOT;
  }
}

// op FRT, FRA, FRB
class PSForm_y2<bits<10> psyop, dag OOL, dag IOL, string asmstr,
                 InstrItinClass itin>
    : PSForm_y<psyop, OOL, IOL, asmstr, itin> {
  let FRA = 0;
}

// op. FRT, FRB
multiclass PSForm_y2r<bits<10> psyop, dag OOL, dag IOL, string asmbase,
                      string asmstr, InstrItinClass itin> {
  let BaseName = asmbase in {
    def NAME : PSForm_y2<psyop, OOL, IOL,
                         !strconcat(asmbase, !strconcat(" ", asmstr)), itin>;
    let Defs = [CR1] in
    def o    : PSForm_y2<psyop, OOL, IOL,
                         !strconcat(asmbase, !strconcat(". ", asmstr)), itin>,
                         isDOT;
  }
}

defm PS_DIV : PSForm_x1r<18, (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRB),
                      "ps_div", "$FRT, $FRA, $FRB", IIC_FPGeneral>;
defm PS_SUB : PSForm_x1r<20, (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRB),
                      "ps_sub", "$FRT, $FRA, $FRB", IIC_FPGeneral>;
defm PS_ADD : PSForm_x1r<21, (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRB),
                      "ps_add", "$FRT, $FRA, $FRB", IIC_FPGeneral>;
defm PS_SEL : PSForm_xr<23,
                      (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRC, f8rc:$FRB),
                      "ps_sel", "$FRT, $FRA, $FRC, $FRB", IIC_FPGeneral>;
defm PS_RES : PSForm_x2r<24, (outs f8rc:$FRT), (ins f8rc:$FRB),
                      "ps_res", "$FRT, $FRB", IIC_FPGeneral>;
defm PS_MUL : PSForm_x3r<25, (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRC),
                      "ps_mul", "$FRT, $FRA, $FRC", IIC_FPGeneral>;
defm PS_RSQRTE : PSForm_x2r<26, (outs f8rc:$FRT), (ins f8rc:$FRB),
                      "ps_rsqrte", "$FRT, $FRB", IIC_FPGeneral>;
defm PS_MSUB : PSForm_xr<28,
                      (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRC, f8rc:$FRB),
                      "ps_msub", "$FRT, $FRA, $FRC, $FRB", IIC_FPGeneral>;
defm PS_MADD : PSForm_xr<29,
                      (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRC, f8rc:$FRB),
                      "ps_madd", "$FRT, $FRA, $FRC, $FRB", IIC_FPGeneral>;
defm PS_NMSUB : PSForm_xr<30,
                      (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRC, f8rc:$FRB),
                      "ps_nmsub", "$FRT, $FRA, $FRC, $FRB", IIC_FPGeneral>;
defm PS_NMADD : PSForm_xr<31,
                      (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRC, f8rc:$FRB),
                      "ps_nmadd", "$FRT, $FRA, $FRC, $FRB", IIC_FPGeneral>;
defm PS_NEG : PSForm_y2r<40, (outs f8rc:$FRT), (ins f8rc:$FRB),
                      "ps_neg", "$FRT, $FRB", IIC_FPGeneral>;
defm PS_MR : PSForm_y2r<72, (outs f8rc:$FRT), (ins f8rc:$FRB),
                      "ps_mr", "$FRT, $FRB", IIC_FPGeneral>;
defm PS_NABS : PSForm_y2r<136, (outs f8rc:$FRT), (ins f8rc:$FRB),
                      "ps_nabs", "$FRT, $FRB", IIC_FPGeneral>;
defm PS_ABS : PSForm_y2r<264, (outs f8rc:$FRT), (ins f8rc:$FRB),
                      "ps_abs", "$FRT, $FRB", IIC_FPGeneral>;
defm PS_SUM0 : PSForm_xr<10,
                      (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRC, f8rc:$FRB),
                      "ps_sum0", "$FRT, $FRA, $FRC, $FRB", IIC_FPGeneral>;
defm PS_SUM1 : PSForm_xr<11,
                      (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRC, f8rc:$FRB),
                      "ps_sum1", "$FRT, $FRA, $FRC, $FRB", IIC_FPGeneral>;
defm PS_MULS0 : PSForm_x3r<12, (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRC),
                      "ps_muls0", "$FRT, $FRA, $FRC", IIC_FPGeneral>;
defm PS_MULS1 : PSForm_x3r<13, (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRC),
                      "ps_muls1", "$FRT, $FRA, $FRC", IIC_FPGeneral>;
defm PS_MADDS0 : PSForm_xr<14,
                      (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRC, f8rc:$FRB),
                      "ps_madds0", "$FRT, $FRA, $FRC, $FRB", IIC_FPGeneral>;
defm PS_MADDS1 : PSForm_xr<15,
                      (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRC, f8rc:$FRB),
                      "ps_madds1", "$FRT, $FRA, $FRC, $FRB", IIC_FPGeneral>;
def PS_CMPU0 : PSForm_c<0,
                      (outs crrc:$crD), (ins f8rc:$FRA, f8rc:$FRB),
                      "ps_cmpu0 $crD, $FRA, $FRB", IIC_FPGeneral>;
def PS_CMPO0 : PSForm_c<32,
                      (outs crrc:$crD), (ins f8rc:$FRA, f8rc:$FRB),
                      "ps_cmpo0 $crD, $FRA, $FRB", IIC_FPGeneral>;
def PS_CMPU1 : PSForm_c<64,
                      (outs crrc:$crD), (ins f8rc:$FRA, f8rc:$FRB),
                      "ps_cmpu1 $crD, $FRA, $FRB", IIC_FPGeneral>;
def PS_CMPO1 : PSForm_c<96,
                      (outs crrc:$crD), (ins f8rc:$FRA, f8rc:$FRB),
                      "ps_cmpo1 $crD, $FRA, $FRB", IIC_FPGeneral>;
defm PS_MERGE00 : PSForm_yr<528,
                      (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRB),
                      "ps_merge00", "$FRT, $FRA, $FRB", IIC_FPGeneral>;
defm PS_MERGE01 : PSForm_yr<560,
                      (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRB),
                      "ps_merge01", "$FRT, $FRA, $FRB", IIC_FPGeneral>;
defm PS_MERGE10 : PSForm_yr<592,
                      (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRB),
                      "ps_merge10", "$FRT, $FRA, $FRB", IIC_FPGeneral>;
defm PS_MERGE11 : PSForm_yr<624,
                      (outs f8rc:$FRT), (ins f8rc:$FRA, f8rc:$FRB),
                      "ps_merge11", "$FRT, $FRA, $FRB", IIC_FPGeneral>;

def PSC_DCBZL : DCBZL_Form<1014,
                           (outs), (ins gprc:$rA, gprc:$rB),
                           "dcbz_l $rA, $rB", IIC_FPGeneral>;

}
}
