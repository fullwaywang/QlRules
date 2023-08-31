/**
 * @name postgresql-3bb3f42f3749d40b8d4de65871e8d828b18d4a45-range
 * @id cpp/postgresql/3bb3f42f3749d40b8d4de65871e8d828b18d4a45/range
 * @description postgresql-3bb3f42f3749d40b8d4de65871e8d828b18d4a45-src/backend/regex/regc_locale.c-range CVE-2016-0773
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vv_403, Variable vnchrs_408, EqualityOperation target_24, EqualityOperation target_25, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("getcvec")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vv_403
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnchrs_408
		and target_24.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_25.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Variable vcv_409, Variable vc_410, VariableAccess target_1) {
		target_1.getTarget()=vc_410
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addchr")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcv_409
}

predicate func_2(Variable vc_410, Variable vlc_411, VariableAccess target_2) {
		target_2.getTarget()=vlc_411
		and target_2.getParent().(AssignExpr).getLValue() = target_2
		and target_2.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pg_wc_tolower")
		and target_2.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_410
}

predicate func_3(Variable vc_410, Variable vlc_411, ExprStmt target_26, VariableAccess target_3) {
		target_3.getTarget()=vc_410
		and target_3.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vlc_411
		and target_3.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_26
}

/*predicate func_4(Variable vc_410, Variable vlc_411, ExprStmt target_26, ExprStmt target_27, ExprStmt target_28, VariableAccess target_4) {
		target_4.getTarget()=vlc_411
		and target_4.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vc_410
		and target_4.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_26
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getParent().(NEExpr).getAnOperand().(VariableAccess).getLocation())
		and target_4.getParent().(NEExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_28.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

*/
predicate func_5(Variable vcv_409, Variable vlc_411, VariableAccess target_5) {
		target_5.getTarget()=vlc_411
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addchr")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcv_409
}

predicate func_6(Variable vc_410, Variable vuc_412, VariableAccess target_6) {
		target_6.getTarget()=vuc_412
		and target_6.getParent().(AssignExpr).getLValue() = target_6
		and target_6.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pg_wc_toupper")
		and target_6.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_410
}

predicate func_7(Variable vc_410, Variable vuc_412, ExprStmt target_29, VariableAccess target_7) {
		target_7.getTarget()=vc_410
		and target_7.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vuc_412
		and target_7.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_29
}

/*predicate func_8(Variable vc_410, Variable vuc_412, ExprStmt target_29, ExprStmt target_28, VariableAccess target_8) {
		target_8.getTarget()=vuc_412
		and target_8.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vc_410
		and target_8.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_29
		and target_28.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getParent().(NEExpr).getAnOperand().(VariableAccess).getLocation())
}

*/
predicate func_9(Function func, Literal target_9) {
		target_9.getValue()="2"
		and not target_9.getValue()="0"
		and target_9.getParent().(MulExpr).getParent().(AddExpr).getAnOperand() instanceof MulExpr
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Function func, Literal target_10) {
		target_10.getValue()="4"
		and not target_10.getValue()="100000"
		and target_10.getParent().(AddExpr).getParent().(AssignExpr).getRValue() instanceof AddExpr
		and target_10.getEnclosingFunction() = func
}

predicate func_11(Variable vcv_409, Variable vuc_412, ReturnStmt target_30, EqualityOperation target_31, FunctionCall target_11) {
		target_11.getTarget().hasName("addchr")
		and not target_11.getTarget().hasName("addrange")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vcv_409
		and target_11.getArgument(1).(VariableAccess).getTarget()=vuc_412
		and target_11.getArgument(0).(VariableAccess).getLocation().isBefore(target_30.getExpr().(VariableAccess).getLocation())
		and target_31.getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getArgument(1).(VariableAccess).getLocation())
}

predicate func_12(Variable vnchrs_408, ExprStmt target_32, Function func) {
	exists(IfStmt target_12 |
		target_12.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnchrs_408
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnchrs_408
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="100000"
		and target_12.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnchrs_408
		and target_12.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="100000"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_12)
		and target_32.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_12.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

/*predicate func_13(Variable vnchrs_408, ExprStmt target_33) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(VariableAccess).getTarget()=vnchrs_408
		and target_13.getRValue().(Literal).getValue()="100000"
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_13.getLValue().(VariableAccess).getLocation()))
}

*/
predicate func_14(Parameter vb_405, Variable vcv_409, ReturnStmt target_30, Function func) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(FunctionCall).getTarget().hasName("addrange")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcv_409
		and target_14.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("celt")
		and target_14.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vb_405
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_14 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_14)
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_30.getExpr().(VariableAccess).getLocation()))
}

predicate func_16(Parameter va_404, Parameter vb_405, ExprStmt target_26, ExprStmt target_34, RelationalOperation target_35) {
	exists(LogicalAndExpr target_16 |
		target_16.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("celt")
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("celt")
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("before")
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("celt")
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va_404
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("before")
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vb_405
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("celt")
		and target_16.getParent().(IfStmt).getThen()=target_26
		and target_34.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_35.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_17(Parameter vv_403, Variable vcv_409, EqualityOperation target_36, EqualityOperation target_25, ExprStmt target_37, ExprStmt target_26) {
	exists(IfStmt target_17 |
		target_17.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="nchrs"
		and target_17.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcv_409
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="chrspace"
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcv_409
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nexttype"
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_403
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(Literal).getValue()="101"
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="err"
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_403
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="err"
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="err"
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="19"
		and target_17.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_17
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_36
		and target_25.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_37.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_17.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_17.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_26.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_18(Parameter va_404, Parameter vb_405, ExprStmt target_29) {
	exists(LogicalAndExpr target_18 |
		target_18.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("celt")
		and target_18.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("celt")
		and target_18.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("before")
		and target_18.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("celt")
		and target_18.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va_404
		and target_18.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("before")
		and target_18.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vb_405
		and target_18.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("celt")
		and target_18.getParent().(IfStmt).getThen()=target_29)
}

predicate func_19(Parameter vv_403, Variable vcv_409, EqualityOperation target_31, ExprStmt target_26, ExprStmt target_29) {
	exists(IfStmt target_19 |
		target_19.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="nchrs"
		and target_19.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcv_409
		and target_19.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="chrspace"
		and target_19.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcv_409
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nexttype"
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_403
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(Literal).getValue()="101"
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="err"
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_403
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="err"
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="err"
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="19"
		and target_19.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_19
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
		and target_26.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_19.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_20(Parameter vv_403) {
	exists(IfStmt target_20 |
		target_20.getCondition().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cancel_requested"
		and target_20.getCondition().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="re_fns"
		and target_20.getCondition().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="re"
		and target_20.getCondition().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_403
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nexttype"
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_403
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(Literal).getValue()="101"
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="err"
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_403
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="err"
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="err"
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="21"
		and target_20.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_21(Parameter va_404, Parameter vb_405, AddExpr target_21) {
		target_21.getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vb_405
		and target_21.getAnOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=va_404
		and target_21.getAnOperand().(Literal).getValue()="1"
}

predicate func_23(Variable vnchrs_408, AddExpr target_23) {
		target_23.getAnOperand().(MulExpr).getLeftOperand() instanceof AddExpr
		and target_23.getAnOperand().(MulExpr).getRightOperand() instanceof Literal
		and target_23.getAnOperand() instanceof Literal
		and target_23.getParent().(AssignExpr).getRValue() = target_23
		and target_23.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnchrs_408
}

predicate func_24(Parameter vv_403, EqualityOperation target_24) {
		target_24.getAnOperand().(PointerFieldAccess).getTarget().getName()="err"
		and target_24.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_403
		and target_24.getAnOperand().(Literal).getValue()="0"
}

predicate func_25(Parameter vv_403, EqualityOperation target_25) {
		target_25.getAnOperand().(PointerFieldAccess).getTarget().getName()="err"
		and target_25.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_403
		and target_25.getAnOperand().(Literal).getValue()="0"
}

predicate func_26(Variable vcv_409, Variable vlc_411, ExprStmt target_26) {
		target_26.getExpr().(FunctionCall).getTarget().hasName("addchr")
		and target_26.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcv_409
		and target_26.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlc_411
}

predicate func_27(Variable vc_410, Variable vlc_411, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlc_411
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pg_wc_tolower")
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_410
}

predicate func_28(Variable vc_410, Variable vuc_412, ExprStmt target_28) {
		target_28.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vuc_412
		and target_28.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pg_wc_toupper")
		and target_28.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_410
}

predicate func_29(ExprStmt target_29) {
		target_29.getExpr() instanceof FunctionCall
}

predicate func_30(Variable vcv_409, ReturnStmt target_30) {
		target_30.getExpr().(VariableAccess).getTarget()=vcv_409
}

predicate func_31(Variable vc_410, Variable vuc_412, EqualityOperation target_31) {
		target_31.getAnOperand().(VariableAccess).getTarget()=vc_410
		and target_31.getAnOperand().(VariableAccess).getTarget()=vuc_412
}

predicate func_32(Variable vnchrs_408, ExprStmt target_32) {
		target_32.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnchrs_408
		and target_32.getExpr().(AssignExpr).getRValue() instanceof AddExpr
}

predicate func_33(Parameter vv_403, Variable vnchrs_408, Variable vcv_409, ExprStmt target_33) {
		target_33.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcv_409
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("getcvec")
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vv_403
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnchrs_408
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof Literal
}

predicate func_34(Parameter va_404, Variable vc_410, ExprStmt target_34) {
		target_34.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_410
		and target_34.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=va_404
}

predicate func_35(Parameter vb_405, Variable vc_410, RelationalOperation target_35) {
		 (target_35 instanceof GEExpr or target_35 instanceof LEExpr)
		and target_35.getLesserOperand().(VariableAccess).getTarget()=vc_410
		and target_35.getGreaterOperand().(VariableAccess).getTarget()=vb_405
}

predicate func_36(Variable vc_410, Variable vlc_411, EqualityOperation target_36) {
		target_36.getAnOperand().(VariableAccess).getTarget()=vc_410
		and target_36.getAnOperand().(VariableAccess).getTarget()=vlc_411
}

predicate func_37(Variable vcv_409, Variable vc_410, ExprStmt target_37) {
		target_37.getExpr().(FunctionCall).getTarget().hasName("addchr")
		and target_37.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcv_409
		and target_37.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vc_410
}

from Function func, Parameter vv_403, Parameter va_404, Parameter vb_405, Variable vnchrs_408, Variable vcv_409, Variable vc_410, Variable vlc_411, Variable vuc_412, Literal target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_5, VariableAccess target_6, VariableAccess target_7, Literal target_9, Literal target_10, FunctionCall target_11, AddExpr target_21, AddExpr target_23, EqualityOperation target_24, EqualityOperation target_25, ExprStmt target_26, ExprStmt target_27, ExprStmt target_28, ExprStmt target_29, ReturnStmt target_30, EqualityOperation target_31, ExprStmt target_32, ExprStmt target_33, ExprStmt target_34, RelationalOperation target_35, EqualityOperation target_36, ExprStmt target_37
where
func_0(vv_403, vnchrs_408, target_24, target_25, target_0)
and func_1(vcv_409, vc_410, target_1)
and func_2(vc_410, vlc_411, target_2)
and func_3(vc_410, vlc_411, target_26, target_3)
and func_5(vcv_409, vlc_411, target_5)
and func_6(vc_410, vuc_412, target_6)
and func_7(vc_410, vuc_412, target_29, target_7)
and func_9(func, target_9)
and func_10(func, target_10)
and func_11(vcv_409, vuc_412, target_30, target_31, target_11)
and not func_12(vnchrs_408, target_32, func)
and not func_14(vb_405, vcv_409, target_30, func)
and not func_16(va_404, vb_405, target_26, target_34, target_35)
and not func_17(vv_403, vcv_409, target_36, target_25, target_37, target_26)
and not func_18(va_404, vb_405, target_29)
and not func_19(vv_403, vcv_409, target_31, target_26, target_29)
and not func_20(vv_403)
and func_21(va_404, vb_405, target_21)
and func_23(vnchrs_408, target_23)
and func_24(vv_403, target_24)
and func_25(vv_403, target_25)
and func_26(vcv_409, vlc_411, target_26)
and func_27(vc_410, vlc_411, target_27)
and func_28(vc_410, vuc_412, target_28)
and func_29(target_29)
and func_30(vcv_409, target_30)
and func_31(vc_410, vuc_412, target_31)
and func_32(vnchrs_408, target_32)
and func_33(vv_403, vnchrs_408, vcv_409, target_33)
and func_34(va_404, vc_410, target_34)
and func_35(vb_405, vc_410, target_35)
and func_36(vc_410, vlc_411, target_36)
and func_37(vcv_409, vc_410, target_37)
and vv_403.getType().hasName("vars *")
and va_404.getType().hasName("celt")
and vb_405.getType().hasName("celt")
and vnchrs_408.getType().hasName("int")
and vcv_409.getType().hasName("cvec *")
and vc_410.getType().hasName("celt")
and vlc_411.getType().hasName("celt")
and vuc_412.getType().hasName("celt")
and vv_403.getFunction() = func
and va_404.getFunction() = func
and vb_405.getFunction() = func
and vnchrs_408.(LocalVariable).getFunction() = func
and vcv_409.(LocalVariable).getFunction() = func
and vc_410.(LocalVariable).getFunction() = func
and vlc_411.(LocalVariable).getFunction() = func
and vuc_412.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
