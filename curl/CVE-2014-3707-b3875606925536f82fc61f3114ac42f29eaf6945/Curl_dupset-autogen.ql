/**
 * @name curl-b3875606925536f82fc61f3114ac42f29eaf6945-Curl_dupset
 * @id cpp/curl/b3875606925536f82fc61f3114ac42f29eaf6945/Curl-dupset
 * @description curl-b3875606925536f82fc61f3114ac42f29eaf6945-lib/url.c-Curl_dupset CVE-2014-3707
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdst_346, MulExpr target_0) {
		target_0.getValue()="360"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="str"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_346
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_2(Variable vi_349, ArrayExpr target_11, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_349
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_2)
		and target_11.getArrayOffset().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vdst_346, Parameter vsrc_346, Variable vi_349, ArrayExpr target_11, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="postfieldsize"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_346
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_346
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_349
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_349
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_memdup")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_349
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="postfieldsize"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_349
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="postfields"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_346
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_349
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_3)
		and target_11.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_4(Parameter vdst_346, Parameter vsrc_346, Variable vi_349, ValueFieldAccess target_12, ExprStmt target_13, ArrayExpr target_11) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_346
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_349
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_memdup")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_346
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_349
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="postfieldsize"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_346
		and target_12.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_5(Parameter vdst_346, Variable vi_349) {
	exists(IfStmt target_5 |
		target_5.getCondition().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_5.getCondition().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_5.getCondition().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_346
		and target_5.getCondition().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_349)
}

*/
/*predicate func_6(Parameter vdst_346, Variable vi_349, AddressOfExpr target_14) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="postfields"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_346
		and target_6.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_6.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_6.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_346
		and target_6.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_349
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_7(Function func) {
	exists(ReturnStmt target_7 |
		(func.getEntryPoint().(BlockStmt).getStmt(7)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_7))
}

predicate func_8(Variable vresult_348, Function func, ReturnStmt target_8) {
		target_8.getExpr().(VariableAccess).getTarget()=vresult_348
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(VariableAccess target_15, Function func, BreakStmt target_9) {
		target_9.toString() = "break;"
		and target_9.getParent().(IfStmt).getCondition()=target_15
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Function func, LabelStmt target_10) {
		target_10.toString() = "label ...:"
		and target_10.getEnclosingFunction() = func
}

predicate func_11(Parameter vsrc_346, Variable vi_349, ArrayExpr target_11) {
		target_11.getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_11.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_11.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_346
		and target_11.getArrayOffset().(VariableAccess).getTarget()=vi_349
}

predicate func_12(Parameter vdst_346, ValueFieldAccess target_12) {
		target_12.getTarget().getName()="str"
		and target_12.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_12.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_346
}

predicate func_13(Parameter vdst_346, Parameter vsrc_346, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="set"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_346
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="set"
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_346
}

predicate func_14(Parameter vdst_346, Variable vi_349, AddressOfExpr target_14) {
		target_14.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_14.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_14.getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_346
		and target_14.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_349
}

predicate func_15(Variable vresult_348, VariableAccess target_15) {
		target_15.getTarget()=vresult_348
}

from Function func, Parameter vdst_346, Parameter vsrc_346, Variable vresult_348, Variable vi_349, MulExpr target_0, ReturnStmt target_8, BreakStmt target_9, LabelStmt target_10, ArrayExpr target_11, ValueFieldAccess target_12, ExprStmt target_13, AddressOfExpr target_14, VariableAccess target_15
where
func_0(vdst_346, target_0)
and not func_2(vi_349, target_11, func)
and not func_3(vdst_346, vsrc_346, vi_349, target_11, func)
and not func_7(func)
and func_8(vresult_348, func, target_8)
and func_9(target_15, func, target_9)
and func_10(func, target_10)
and func_11(vsrc_346, vi_349, target_11)
and func_12(vdst_346, target_12)
and func_13(vdst_346, vsrc_346, target_13)
and func_14(vdst_346, vi_349, target_14)
and func_15(vresult_348, target_15)
and vdst_346.getType().hasName("SessionHandle *")
and vsrc_346.getType().hasName("SessionHandle *")
and vresult_348.getType().hasName("CURLcode")
and vi_349.getType().hasName("dupstring")
and vdst_346.getParentScope+() = func
and vsrc_346.getParentScope+() = func
and vresult_348.getParentScope+() = func
and vi_349.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
