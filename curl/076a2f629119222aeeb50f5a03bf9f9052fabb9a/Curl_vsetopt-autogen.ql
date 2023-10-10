/**
 * @name curl-076a2f629119222aeeb50f5a03bf9f9052fabb9a-Curl_vsetopt
 * @id cpp/curl/076a2f629119222aeeb50f5a03bf9f9052fabb9a/Curl-vsetopt
 * @description curl-076a2f629119222aeeb50f5a03bf9f9052fabb9a-lib/setopt.c-Curl_vsetopt CVE-2023-23914
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_189, PointerFieldAccess target_18) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18)
}

/*predicate func_1(Parameter vdata_189) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_1.getRValue().(Literal).getValue()="0")
}

*/
predicate func_2(Parameter vdata_189, PointerFieldAccess target_21, ExprStmt target_22, PointerFieldAccess target_23) {
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
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
		and target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_23.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vdata_189, Variable vargptr_191, VariableAccess target_24, AddressOfExpr target_25, IfStmt target_26) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("curl_slist *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("curl_slist_append")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="hstslist"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vargptr_191
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
		and target_25.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_26.getCondition().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vdata_189, VariableAccess target_24) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("curl_slist *")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("curl_slist_free_all")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="hstslist"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="hstslist"
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24)
}

predicate func_5(Parameter vdata_189, VariableAccess target_24) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="hstslist"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("curl_slist *")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24)
}

predicate func_6(Parameter vdata_189, VariableAccess target_24) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("curl_slist_free_all")
		and target_6.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="hstslist"
		and target_6.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_6.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24)
}

predicate func_7(Parameter vdata_189, VariableAccess target_24) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="hstslist"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24)
}

predicate func_8(Parameter vdata_189, VariableAccess target_24) {
	exists(IfStmt target_8 |
		target_8.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="share"
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_8.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_hsts_cleanup")
		and target_8.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_8.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24)
}

predicate func_9(Parameter vdata_189, VariableAccess target_27, IfStmt target_9) {
		target_9.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_9.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_hsts_init")
		and target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_9.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_27
}

predicate func_10(Parameter vparam_189, Variable vargptr_191, VariableAccess target_27, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vargptr_191
		and target_10.getExpr().(AssignExpr).getRValue().(BuiltInVarArg).getVAList().(VariableAccess).getTarget()=vparam_189
		and target_10.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_27
}

predicate func_11(Variable vargptr_191, Variable vresult_192, VariableAccess target_27, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_192
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_setstropt")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vargptr_191
		and target_11.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_27
}

predicate func_12(Variable vresult_192, VariableAccess target_27, IfStmt target_12) {
		target_12.getCondition().(VariableAccess).getTarget()=vresult_192
		and target_12.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vresult_192
		and target_12.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_27
}

predicate func_13(Parameter vdata_189, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="hsts"
		and target_13.getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_14(Parameter vdata_189, VariableAccess target_14) {
		target_14.getTarget()=vdata_189
		and target_14.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_15(Variable vargptr_191, VariableAccess target_15) {
		target_15.getTarget()=vargptr_191
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_16(VariableAccess target_27, Function func, BreakStmt target_16) {
		target_16.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_27
		and target_16.getEnclosingFunction() = func
}

predicate func_17(Parameter vdata_189, Variable vargptr_191, FunctionCall target_17) {
		target_17.getTarget().hasName("Curl_hsts_loadfile")
		and target_17.getArgument(0).(VariableAccess).getTarget()=vdata_189
		and target_17.getArgument(1).(PointerFieldAccess).getTarget().getName()="hsts"
		and target_17.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_17.getArgument(2).(VariableAccess).getTarget()=vargptr_191
}

predicate func_18(Parameter vdata_189, PointerFieldAccess target_18) {
		target_18.getTarget().getName()="share"
		and target_18.getQualifier().(VariableAccess).getTarget()=vdata_189
}

predicate func_21(Parameter vdata_189, PointerFieldAccess target_21) {
		target_21.getTarget().getName()="share"
		and target_21.getQualifier().(VariableAccess).getTarget()=vdata_189
}

predicate func_22(Parameter vdata_189, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cookies"
		and target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
		and target_22.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="cookies"
		and target_22.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_22.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
}

predicate func_23(Parameter vdata_189, PointerFieldAccess target_23) {
		target_23.getTarget().getName()="sslsession"
		and target_23.getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_23.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
}

predicate func_24(Variable vargptr_191, VariableAccess target_24) {
		target_24.getTarget()=vargptr_191
}

predicate func_25(Parameter vdata_189, AddressOfExpr target_25) {
		target_25.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_25.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_25.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_189
}

predicate func_26(Variable vargptr_191, IfStmt target_26) {
		target_26.getCondition().(VariableAccess).getTarget()=vargptr_191
		and target_26.getThen().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_27(Parameter voption_189, VariableAccess target_27) {
		target_27.getTarget()=voption_189
}

from Function func, Parameter vdata_189, Parameter voption_189, Parameter vparam_189, Variable vargptr_191, Variable vresult_192, IfStmt target_9, ExprStmt target_10, ExprStmt target_11, IfStmt target_12, PointerFieldAccess target_13, VariableAccess target_14, VariableAccess target_15, BreakStmt target_16, FunctionCall target_17, PointerFieldAccess target_18, PointerFieldAccess target_21, ExprStmt target_22, PointerFieldAccess target_23, VariableAccess target_24, AddressOfExpr target_25, IfStmt target_26, VariableAccess target_27
where
not func_0(vdata_189, target_18)
and not func_2(vdata_189, target_21, target_22, target_23)
and not func_3(vdata_189, vargptr_191, target_24, target_25, target_26)
and not func_4(vdata_189, target_24)
and not func_5(vdata_189, target_24)
and not func_6(vdata_189, target_24)
and not func_7(vdata_189, target_24)
and not func_8(vdata_189, target_24)
and func_9(vdata_189, target_27, target_9)
and func_10(vparam_189, vargptr_191, target_27, target_10)
and func_11(vargptr_191, vresult_192, target_27, target_11)
and func_12(vresult_192, target_27, target_12)
and func_13(vdata_189, target_13)
and func_14(vdata_189, target_14)
and func_15(vargptr_191, target_15)
and func_16(target_27, func, target_16)
and func_17(vdata_189, vargptr_191, target_17)
and func_18(vdata_189, target_18)
and func_21(vdata_189, target_21)
and func_22(vdata_189, target_22)
and func_23(vdata_189, target_23)
and func_24(vargptr_191, target_24)
and func_25(vdata_189, target_25)
and func_26(vargptr_191, target_26)
and func_27(voption_189, target_27)
and vdata_189.getType().hasName("Curl_easy *")
and voption_189.getType().hasName("CURLoption")
and vparam_189.getType().hasName("va_list")
and vargptr_191.getType().hasName("char *")
and vresult_192.getType().hasName("CURLcode")
and vdata_189.getFunction() = func
and voption_189.getFunction() = func
and vparam_189.getFunction() = func
and vargptr_191.(LocalVariable).getFunction() = func
and vresult_192.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
