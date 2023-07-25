/**
 * @name curl-076a2f629119222aeeb50f5a03bf9f9052fabb9a-Curl_vsetopt
 * @id cpp/curl/076a2f629119222aeeb50f5a03bf9f9052fabb9a/Curl-vsetopt
 * @description curl-076a2f629119222aeeb50f5a03bf9f9052fabb9a-lib/setopt.c-Curl_vsetopt CVE-2023-23914
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_189, BlockStmt target_15, NotExpr target_16) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_0.getParent().(IfStmt).getThen()=target_15
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdata_189, AddressOfExpr target_17) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_1.getRValue().(Literal).getValue()="0"
		and target_17.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vdata_189, PointerFieldAccess target_4, ExprStmt target_19, PointerFieldAccess target_20) {
	exists(IfStmt target_2 |
		target_2.getCondition().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_2.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_2.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_hsts_cleanup")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_20.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vdata_189, Variable vargptr_191, ExprStmt target_7) {
	exists(IfStmt target_3 |
		target_3.getCondition().(VariableAccess).getTarget()=vargptr_191
		and target_3.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("curl_slist *")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("curl_slist_append")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="hstslist"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vargptr_191
		and target_3.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("curl_slist *")
		and target_3.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("curl_slist_free_all")
		and target_3.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="hstslist"
		and target_3.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="hstslist"
		and target_3.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="hstslist"
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("curl_slist *")
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("curl_slist_free_all")
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="hstslist"
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_3.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="hstslist"
		and target_3.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_3.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="share"
		and target_3.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_3.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_3.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_3.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_hsts_cleanup")
		and target_3.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_3.getCondition().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vdata_189, BlockStmt target_15, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="share"
		and target_4.getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_4.getParent().(IfStmt).getThen()=target_15
}

predicate func_5(Parameter vdata_189, VariableAccess target_21, IfStmt target_5) {
		target_5.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_5.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_hsts_init")
		and target_5.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_5.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_5.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_21
}

predicate func_6(Parameter vparam_189, Variable vargptr_191, VariableAccess target_21, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vargptr_191
		and target_6.getExpr().(AssignExpr).getRValue().(BuiltInVarArg).getVAList().(VariableAccess).getTarget()=vparam_189
		and target_6.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_21
}

predicate func_7(Variable vargptr_191, Variable vresult_192, VariableAccess target_21, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_192
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_setstropt")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vargptr_191
		and target_7.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_21
}

predicate func_8(Variable vresult_192, VariableAccess target_21, IfStmt target_8) {
		target_8.getCondition().(VariableAccess).getTarget()=vresult_192
		and target_8.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vresult_192
		and target_8.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_21
}

predicate func_9(Parameter vdata_189, PointerFieldAccess target_9) {
		target_9.getTarget().getName()="hsts"
		and target_9.getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_10(Variable vargptr_191, ExprStmt target_22, VariableAccess target_10) {
		target_10.getTarget()=vargptr_191
		and target_10.getParent().(IfStmt).getThen()=target_22
}

predicate func_11(VariableAccess target_21, Function func, BreakStmt target_11) {
		target_11.toString() = "break;"
		and target_11.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_21
		and target_11.getEnclosingFunction() = func
}

predicate func_12(Parameter vdata_189, VariableAccess target_12) {
		target_12.getTarget()=vdata_189
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_13(Variable vargptr_191, VariableAccess target_13) {
		target_13.getTarget()=vargptr_191
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_14(Parameter vdata_189, Variable vargptr_191, FunctionCall target_14) {
		target_14.getTarget().hasName("Curl_hsts_loadfile")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vdata_189
		and target_14.getArgument(1).(PointerFieldAccess).getTarget().getName()="hsts"
		and target_14.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_14.getArgument(2).(VariableAccess).getTarget()=vargptr_191
}

predicate func_15(Parameter vdata_189, BlockStmt target_15) {
		target_15.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_share_lock")
		and target_15.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_189
		and target_15.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dirty"
		and target_15.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_15.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
}

predicate func_16(Parameter vdata_189, NotExpr target_16) {
		target_16.getOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_16.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
}

predicate func_17(Parameter vdata_189, AddressOfExpr target_17) {
		target_17.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_17.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_17.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
}

predicate func_19(Parameter vdata_189, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cookies"
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_19.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="cookies"
		and target_19.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_19.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
}

predicate func_20(Parameter vdata_189, PointerFieldAccess target_20) {
		target_20.getTarget().getName()="sslsession"
		and target_20.getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_20.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
}

predicate func_21(Parameter voption_189, VariableAccess target_21) {
		target_21.getTarget()=voption_189
}

predicate func_22(ExprStmt target_22) {
		target_22.getExpr() instanceof FunctionCall
}

from Function func, Parameter vdata_189, Parameter voption_189, Parameter vparam_189, Variable vargptr_191, Variable vresult_192, PointerFieldAccess target_4, IfStmt target_5, ExprStmt target_6, ExprStmt target_7, IfStmt target_8, PointerFieldAccess target_9, VariableAccess target_10, BreakStmt target_11, VariableAccess target_12, VariableAccess target_13, FunctionCall target_14, BlockStmt target_15, NotExpr target_16, AddressOfExpr target_17, ExprStmt target_19, PointerFieldAccess target_20, VariableAccess target_21, ExprStmt target_22
where
not func_0(vdata_189, target_15, target_16)
and not func_1(vdata_189, target_17)
and not func_2(vdata_189, target_4, target_19, target_20)
and not func_3(vdata_189, vargptr_191, target_7)
and func_4(vdata_189, target_15, target_4)
and func_5(vdata_189, target_21, target_5)
and func_6(vparam_189, vargptr_191, target_21, target_6)
and func_7(vargptr_191, vresult_192, target_21, target_7)
and func_8(vresult_192, target_21, target_8)
and func_9(vdata_189, target_9)
and func_10(vargptr_191, target_22, target_10)
and func_11(target_21, func, target_11)
and func_12(vdata_189, target_12)
and func_13(vargptr_191, target_13)
and func_14(vdata_189, vargptr_191, target_14)
and func_15(vdata_189, target_15)
and func_16(vdata_189, target_16)
and func_17(vdata_189, target_17)
and func_19(vdata_189, target_19)
and func_20(vdata_189, target_20)
and func_21(voption_189, target_21)
and func_22(target_22)
and vdata_189.getType().hasName("Curl_easy *")
and voption_189.getType().hasName("CURLoption")
and vparam_189.getType().hasName("va_list")
and vargptr_191.getType().hasName("char *")
and vresult_192.getType().hasName("CURLcode")
and vdata_189.getParentScope+() = func
and voption_189.getParentScope+() = func
and vparam_189.getParentScope+() = func
and vargptr_191.getParentScope+() = func
and vresult_192.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
