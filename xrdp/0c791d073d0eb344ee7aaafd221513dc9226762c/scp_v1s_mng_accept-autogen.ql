/**
 * @name xrdp-0c791d073d0eb344ee7aaafd221513dc9226762c-scp_v1s_mng_accept
 * @id cpp/xrdp/0c791d073d0eb344ee7aaafd221513dc9226762c/scp-v1s-mng-accept
 * @description xrdp-0c791d073d0eb344ee7aaafd221513dc9226762c-sesman/libscp/libscp_v1s_mng.c-scp_v1s_mng_accept CVE-2020-4044
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("SCP_SERVER_STATES_E")
		and target_1.getRValue() instanceof EnumConstantAccess
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vsession_45, Parameter vc_43, EqualityOperation target_6, ExprStmt target_7) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getType().hasName("SCP_SERVER_STATES_E")
		and target_2.getRValue().(FunctionCall).getTarget().hasName("scp_v1s_mng_init_session")
		and target_2.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_43
		and target_2.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsession_45
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_2.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Variable vsession_45) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=vsession_45
		and target_4.getRValue() instanceof Literal)
}

predicate func_6(Variable vsession_45, BlockStmt target_79, EqualityOperation target_6) {
		target_6.getAnOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(VariableAccess).getTarget()=vsession_45
		and target_6.getParent().(IfStmt).getThen()=target_79
}

predicate func_7(Variable vsession_45, Function func, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("scp_session_set_type")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_45
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_9(Parameter vc_43, VariableAccess target_9) {
		target_9.getTarget()=vc_43
}

predicate func_11(Variable vsession_45, VariableAccess target_11) {
		target_11.getTarget()=vsession_45
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_14(Function func, DeclStmt target_14) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Function func, DeclStmt target_15) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_15
}

predicate func_16(Function func, DeclStmt target_16) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_16
}

predicate func_17(Variable vcmd_47, Parameter vc_43, Function func, DoStmt target_17) {
		target_17.getCondition() instanceof Literal
		and target_17.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcmd_47
		and target_17.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_17.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_17.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_17.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_17.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_17.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignLShiftExpr).getLValue().(VariableAccess).getTarget()=vcmd_47
		and target_17.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignLShiftExpr).getRValue().(Literal).getValue()="8"
		and target_17.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vcmd_47
		and target_17.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_17.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_17.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_17.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_17.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_17
}

/*predicate func_18(Variable vcmd_47, Parameter vc_43, AssignExpr target_18) {
		target_18.getLValue().(VariableAccess).getTarget()=vcmd_47
		and target_18.getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_18.getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_18.getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_19(Parameter vc_43, PostfixIncrExpr target_19) {
		target_19.getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_19.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_19.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_20(Variable vcmd_47, AssignLShiftExpr target_20) {
		target_20.getLValue().(VariableAccess).getTarget()=vcmd_47
		and target_20.getRValue().(Literal).getValue()="8"
}

*/
/*predicate func_21(Variable vcmd_47, Parameter vc_43, ExprStmt target_21) {
		target_21.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vcmd_47
		and target_21.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_21.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_21.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_22(Parameter vc_43, ExprStmt target_29, ExprStmt target_22) {
		target_22.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_22.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_22.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_22.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_29.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_23(Variable vcmd_47, BlockStmt target_80, VariableAccess target_23) {
		target_23.getTarget()=vcmd_47
		and target_23.getParent().(NEExpr).getAnOperand().(Literal).getValue()="1"
		and target_23.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_80
}

predicate func_25(EqualityOperation target_81, Function func, ReturnStmt target_25) {
		target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_81
		and target_25.getEnclosingFunction() = func
}

predicate func_26(EqualityOperation target_6, Function func, ReturnStmt target_26) {
		target_26.getExpr() instanceof EnumConstantAccess
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_26.getEnclosingFunction() = func
}

predicate func_27(Variable vsession_45, Function func, ExprStmt target_27) {
		target_27.getExpr().(FunctionCall).getTarget().hasName("scp_session_set_version")
		and target_27.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_45
		and target_27.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_27
}

predicate func_28(Variable vsz_48, Parameter vc_43, ExprStmt target_31, PointerFieldAccess target_82, Function func, DoStmt target_28) {
		target_28.getCondition().(Literal).getValue()="0"
		and target_28.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsz_48
		and target_28.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_28.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_28.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_28.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_28.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_28
		and target_28.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_31.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_28.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_82.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_29(Variable vsz_48, Parameter vc_43, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsz_48
		and target_29.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_29.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_29.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

/*predicate func_30(Parameter vc_43, ExprStmt target_30) {
		target_30.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_30.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_30.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
predicate func_31(Variable vsz_48, Variable vbuf_49, ExprStmt target_31) {
		target_31.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_49
		and target_31.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vsz_48
		and target_31.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

predicate func_32(Variable vsz_48, Variable vbuf_49, Parameter vc_43, DoStmt target_32) {
		target_32.getCondition().(Literal).getValue()="0"
		and target_32.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("g_memcpy")
		and target_32.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_49
		and target_32.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="p"
		and target_32.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_32.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_32.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsz_48
		and target_32.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="p"
		and target_32.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_32.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_32.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vsz_48
}

/*predicate func_33(Variable vsz_48, Variable vbuf_49, Parameter vc_43, ExprStmt target_33) {
		target_33.getExpr().(FunctionCall).getTarget().hasName("g_memcpy")
		and target_33.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_49
		and target_33.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="p"
		and target_33.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_33.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_33.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsz_48
}

*/
/*predicate func_34(Variable vsz_48, Parameter vc_43, ExprStmt target_34) {
		target_34.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="p"
		and target_34.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_34.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_34.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vsz_48
}

*/
predicate func_35(Variable vsession_45, Variable vbuf_49, IfStmt target_35) {
		target_35.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_35.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("scp_session_set_username")
		and target_35.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_45
		and target_35.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_49
		and target_35.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("scp_session_destroy")
		and target_35.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_45
}

predicate func_37(Variable vsz_48, Parameter vc_43, DoStmt target_37) {
		target_37.getCondition().(Literal).getValue()="0"
		and target_37.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsz_48
		and target_37.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_37.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_37.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_37.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_37.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

/*predicate func_38(Variable vsz_48, Parameter vc_43, ExprStmt target_38) {
		target_38.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsz_48
		and target_38.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_38.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_38.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_39(Parameter vc_43, ExprStmt target_39) {
		target_39.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_39.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_39.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
predicate func_40(Variable vsz_48, Variable vbuf_49, ExprStmt target_40) {
		target_40.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_49
		and target_40.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vsz_48
		and target_40.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

predicate func_41(Variable vsz_48, Variable vbuf_49, Parameter vc_43, DoStmt target_41) {
		target_41.getCondition().(Literal).getValue()="0"
		and target_41.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("g_memcpy")
		and target_41.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_49
		and target_41.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="p"
		and target_41.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_41.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_41.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsz_48
		and target_41.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="p"
		and target_41.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_41.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_41.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vsz_48
}

/*predicate func_42(Variable vsz_48, Variable vbuf_49, Parameter vc_43, ExprStmt target_42) {
		target_42.getExpr().(FunctionCall).getTarget().hasName("g_memcpy")
		and target_42.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_49
		and target_42.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="p"
		and target_42.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_42.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_42.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsz_48
}

*/
/*predicate func_43(Variable vsz_48, Parameter vc_43, ExprStmt target_43) {
		target_43.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="p"
		and target_43.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_43.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_43.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vsz_48
}

*/
predicate func_44(Variable vsession_45, Variable vbuf_49, IfStmt target_44) {
		target_44.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_44.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("scp_session_set_password")
		and target_44.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_45
		and target_44.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_49
		and target_44.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("scp_session_destroy")
		and target_44.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_45
}

/*predicate func_45(Variable vsession_45, ExprStmt target_45) {
		target_45.getExpr().(FunctionCall).getTarget().hasName("scp_session_destroy")
		and target_45.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_45
}

*/
predicate func_47(Variable vsz_48, Parameter vc_43, DoStmt target_47) {
		target_47.getCondition().(Literal).getValue()="0"
		and target_47.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsz_48
		and target_47.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_47.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_47.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_47.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_47.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

/*predicate func_48(Variable vsz_48, Parameter vc_43, ExprStmt target_48) {
		target_48.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsz_48
		and target_48.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_48.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_48.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_49(Parameter vc_43, ExprStmt target_49) {
		target_49.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_49.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_49.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
predicate func_50(Variable vsession_45, Variable vipaddr_46, Variable vsz_48, Variable vbuf_49, IfStmt target_50) {
		target_50.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsz_48
		and target_50.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignLShiftExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignLShiftExpr).getRValue().(Literal).getValue()="8"
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignLShiftExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignLShiftExpr).getRValue().(Literal).getValue()="8"
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignLShiftExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignLShiftExpr).getRValue().(Literal).getValue()="8"
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_50.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_50.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("scp_session_set_addr")
		and target_50.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_45
		and target_50.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsz_48
		and target_50.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vipaddr_46
		and target_50.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsz_48
		and target_50.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_50.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_50.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("g_memcpy")
		and target_50.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("scp_session_set_addr")
		and target_50.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_45
		and target_50.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsz_48
		and target_50.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuf_49
}

/*predicate func_51(Variable vipaddr_46, Parameter vc_43, DoStmt target_51) {
		target_51.getCondition().(Literal).getValue()="0"
		and target_51.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_51.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_51.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_51.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_51.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_51.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_51.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignLShiftExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_51.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignLShiftExpr).getRValue().(Literal).getValue()="8"
		and target_51.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_51.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_51.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_51.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_51.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_51.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_51.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignLShiftExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_51.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignLShiftExpr).getRValue().(Literal).getValue()="8"
		and target_51.getStmt().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_51.getStmt().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_51.getStmt().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_51.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_51.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_51.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_51.getStmt().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignLShiftExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_51.getStmt().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignLShiftExpr).getRValue().(Literal).getValue()="8"
		and target_51.getStmt().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_51.getStmt().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_51.getStmt().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_51.getStmt().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_51.getStmt().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_51.getStmt().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_52(Variable vipaddr_46, Parameter vc_43, ExprStmt target_52) {
		target_52.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_52.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_52.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_52.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_53(Parameter vc_43, ExprStmt target_53) {
		target_53.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_53.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_53.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_54(Variable vipaddr_46, ExprStmt target_54) {
		target_54.getExpr().(AssignLShiftExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_54.getExpr().(AssignLShiftExpr).getRValue().(Literal).getValue()="8"
}

*/
/*predicate func_55(Variable vipaddr_46, Parameter vc_43, ExprStmt target_55) {
		target_55.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_55.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_55.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_55.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_56(Parameter vc_43, ExprStmt target_56) {
		target_56.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_56.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_56.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_57(Variable vipaddr_46, ExprStmt target_57) {
		target_57.getExpr().(AssignLShiftExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_57.getExpr().(AssignLShiftExpr).getRValue().(Literal).getValue()="8"
}

*/
/*predicate func_58(Variable vipaddr_46, Parameter vc_43, ExprStmt target_58) {
		target_58.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_58.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_58.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_58.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_59(Parameter vc_43, ExprStmt target_59) {
		target_59.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_59.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_59.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_60(Variable vipaddr_46, ExprStmt target_60) {
		target_60.getExpr().(AssignLShiftExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_60.getExpr().(AssignLShiftExpr).getRValue().(Literal).getValue()="8"
}

*/
/*predicate func_61(Variable vipaddr_46, Parameter vc_43, ExprStmt target_61) {
		target_61.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vipaddr_46
		and target_61.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_61.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_61.getExpr().(AssignOrExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_62(Parameter vc_43, ExprStmt target_62) {
		target_62.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_62.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_62.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_63(Variable vsession_45, Variable vipaddr_46, Variable vsz_48, ExprStmt target_63) {
		target_63.getExpr().(FunctionCall).getTarget().hasName("scp_session_set_addr")
		and target_63.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_45
		and target_63.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsz_48
		and target_63.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vipaddr_46
}

*/
/*predicate func_64(Variable vbuf_49, Parameter vc_43, DoStmt target_64) {
		target_64.getCondition().(Literal).getValue()="0"
		and target_64.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("g_memcpy")
		and target_64.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_49
		and target_64.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="p"
		and target_64.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_64.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_64.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="16"
		and target_64.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="p"
		and target_64.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_64.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_64.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="16"
}

*/
/*predicate func_65(Variable vbuf_49, Parameter vc_43, ExprStmt target_65) {
		target_65.getExpr().(FunctionCall).getTarget().hasName("g_memcpy")
		and target_65.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_49
		and target_65.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="p"
		and target_65.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_65.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_65.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="16"
}

*/
/*predicate func_66(Parameter vc_43, ExprStmt target_66) {
		target_66.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="p"
		and target_66.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_66.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_66.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="16"
}

*/
/*predicate func_67(Variable vsession_45, Variable vsz_48, Variable vbuf_49, ExprStmt target_67) {
		target_67.getExpr().(FunctionCall).getTarget().hasName("scp_session_set_addr")
		and target_67.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_45
		and target_67.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsz_48
		and target_67.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuf_49
}

*/
predicate func_68(Variable vsz_48, Parameter vc_43, DoStmt target_68) {
		target_68.getCondition().(Literal).getValue()="0"
		and target_68.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsz_48
		and target_68.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_68.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_68.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_68.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_68.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

/*predicate func_69(Variable vsz_48, Parameter vc_43, ExprStmt target_69) {
		target_69.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsz_48
		and target_69.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_69.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_69.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
/*predicate func_70(Parameter vc_43, ExprStmt target_70) {
		target_70.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_70.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_70.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

*/
predicate func_71(Variable vsz_48, Variable vbuf_49, ExprStmt target_71) {
		target_71.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_49
		and target_71.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vsz_48
		and target_71.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

predicate func_72(Variable vsz_48, Variable vbuf_49, Parameter vc_43, DoStmt target_72) {
		target_72.getCondition().(Literal).getValue()="0"
		and target_72.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("g_memcpy")
		and target_72.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_49
		and target_72.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="p"
		and target_72.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_72.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_72.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsz_48
		and target_72.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="p"
		and target_72.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_72.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_72.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vsz_48
}

/*predicate func_73(Variable vsz_48, Variable vbuf_49, Parameter vc_43, ExprStmt target_73) {
		target_73.getExpr().(FunctionCall).getTarget().hasName("g_memcpy")
		and target_73.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_49
		and target_73.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="p"
		and target_73.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_73.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_73.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsz_48
}

*/
/*predicate func_74(Variable vsz_48, Parameter vc_43, ExprStmt target_74) {
		target_74.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="p"
		and target_74.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_74.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
		and target_74.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vsz_48
}

*/
predicate func_75(Variable vsession_45, Variable vbuf_49, IfStmt target_75) {
		target_75.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_75.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("scp_session_set_hostname")
		and target_75.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_45
		and target_75.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_49
		and target_75.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("scp_session_destroy")
		and target_75.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_45
}

/*predicate func_76(Variable vsession_45, ExprStmt target_76) {
		target_76.getExpr().(FunctionCall).getTarget().hasName("scp_session_destroy")
		and target_76.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_45
}

*/
predicate func_78(Function func, ReturnStmt target_78) {
		target_78.getExpr() instanceof EnumConstantAccess
		and target_78.getEnclosingFunction() = func
}

predicate func_79(BlockStmt target_79) {
		target_79.getStmt(0) instanceof ReturnStmt
}

predicate func_80(BlockStmt target_80) {
		target_80.getStmt(0) instanceof ReturnStmt
}

predicate func_81(Variable vcmd_47, EqualityOperation target_81) {
		target_81.getAnOperand().(VariableAccess).getTarget()=vcmd_47
		and target_81.getAnOperand() instanceof Literal
}

predicate func_82(Parameter vc_43, PointerFieldAccess target_82) {
		target_82.getTarget().getName()="p"
		and target_82.getQualifier().(PointerFieldAccess).getTarget().getName()="in_s"
		and target_82.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_43
}

from Function func, Variable vsession_45, Variable vipaddr_46, Variable vcmd_47, Variable vsz_48, Variable vbuf_49, Parameter vc_43, EqualityOperation target_6, ExprStmt target_7, VariableAccess target_9, VariableAccess target_11, DeclStmt target_14, DeclStmt target_15, DeclStmt target_16, DoStmt target_17, VariableAccess target_23, ReturnStmt target_25, ReturnStmt target_26, ExprStmt target_27, DoStmt target_28, ExprStmt target_29, ExprStmt target_31, DoStmt target_32, IfStmt target_35, DoStmt target_37, ExprStmt target_40, DoStmt target_41, IfStmt target_44, DoStmt target_47, IfStmt target_50, DoStmt target_68, ExprStmt target_71, DoStmt target_72, IfStmt target_75, ReturnStmt target_78, BlockStmt target_79, BlockStmt target_80, EqualityOperation target_81, PointerFieldAccess target_82
where
not func_1(func)
and not func_2(vsession_45, vc_43, target_6, target_7)
and not func_4(vsession_45)
and func_6(vsession_45, target_79, target_6)
and func_7(vsession_45, func, target_7)
and func_9(vc_43, target_9)
and func_11(vsession_45, target_11)
and func_14(func, target_14)
and func_15(func, target_15)
and func_16(func, target_16)
and func_17(vcmd_47, vc_43, func, target_17)
and func_23(vcmd_47, target_80, target_23)
and func_25(target_81, func, target_25)
and func_26(target_6, func, target_26)
and func_27(vsession_45, func, target_27)
and func_28(vsz_48, vc_43, target_31, target_82, func, target_28)
and func_29(vsz_48, vc_43, target_29)
and func_31(vsz_48, vbuf_49, target_31)
and func_32(vsz_48, vbuf_49, vc_43, target_32)
and func_35(vsession_45, vbuf_49, target_35)
and func_37(vsz_48, vc_43, target_37)
and func_40(vsz_48, vbuf_49, target_40)
and func_41(vsz_48, vbuf_49, vc_43, target_41)
and func_44(vsession_45, vbuf_49, target_44)
and func_47(vsz_48, vc_43, target_47)
and func_50(vsession_45, vipaddr_46, vsz_48, vbuf_49, target_50)
and func_68(vsz_48, vc_43, target_68)
and func_71(vsz_48, vbuf_49, target_71)
and func_72(vsz_48, vbuf_49, vc_43, target_72)
and func_75(vsession_45, vbuf_49, target_75)
and func_78(func, target_78)
and func_79(target_79)
and func_80(target_80)
and func_81(vcmd_47, target_81)
and func_82(vc_43, target_82)
and vsession_45.getType().hasName("SCP_SESSION *")
and vipaddr_46.getType().hasName("tui32")
and vcmd_47.getType().hasName("tui16")
and vsz_48.getType().hasName("tui8")
and vbuf_49.getType().hasName("char[257]")
and vc_43.getType().hasName("SCP_CONNECTION *")
and vsession_45.getParentScope+() = func
and vipaddr_46.getParentScope+() = func
and vcmd_47.getParentScope+() = func
and vsz_48.getParentScope+() = func
and vbuf_49.getParentScope+() = func
and vc_43.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
