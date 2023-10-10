/**
 * @name varnish-dd47e658a0de9d12c433a4a01fb43ea4fe4d3a41-http1_splitline
 * @id cpp/varnish/dd47e658a0de9d12c433a4a01fb43ea4fe4d3a41/http1-splitline
 * @description varnish-dd47e658a0de9d12c433a4a01fb43ea4fe4d3a41-bin/varnishd/http1/cache_http1_proto.c-http1_splitline CVE-2019-15892
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vhf_218, Variable vp_221, Parameter vhp_218, ArrayExpr target_8, PointerDereferenceExpr target_10, RelationalOperation target_11, ArrayExpr target_12, VariableAccess target_0) {
		target_0.getTarget()=vp_221
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="b"
		and target_0.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_0.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_218
		and target_0.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhf_218
		and target_0.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_8.getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_10.getOperand().(VariableAccess).getLocation().isBefore(target_0.getLocation())
		and target_0.getLocation().isBefore(target_11.getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Variable vp_221, Variable vq_221, PointerDereferenceExpr target_13, ExprStmt target_14) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vq_221
		and target_1.getRValue().(VariableAccess).getTarget()=vp_221
		and target_13.getOperand().(VariableAccess).getLocation().isBefore(target_1.getRValue().(VariableAccess).getLocation())
		and target_14.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getLValue().(VariableAccess).getLocation()))
}

predicate func_2(Variable vp_221, Variable vq_221, ExprStmt target_6, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_221
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vq_221
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="b"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("char *")
		and target_2.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_2)
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vhf_218, Parameter vhp_218, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="hd"
		and target_3.getQualifier().(VariableAccess).getTarget()=vhp_218
		and target_3.getParent().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhf_218
		and target_3.getParent().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
}

*/
/*predicate func_4(Parameter vhf_218, Parameter vhp_218, ArrayExpr target_4) {
		target_4.getArrayBase().(VariableAccess).getTarget()=vhf_218
		and target_4.getArrayOffset().(Literal).getValue()="2"
		and target_4.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_4.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_218
}

*/
predicate func_5(LogicalAndExpr target_15, Function func, ReturnStmt target_5) {
		target_5.getExpr().(Literal).getValue()="400"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Parameter vhf_218, Variable vp_221, Parameter vhp_218, Function func, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="e"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_218
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhf_218
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_221
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Parameter vhp_218, AssignExpr target_7) {
		target_7.getLValue().(ValueFieldAccess).getTarget().getName()="b"
		and target_7.getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_7.getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_218
		and target_7.getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset() instanceof ArrayExpr
		and target_7.getRValue().(Literal).getValue()="0"
}

predicate func_8(Parameter vhf_218, Parameter vhp_218, ArrayExpr target_8) {
		target_8.getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_8.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_218
		and target_8.getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhf_218
		and target_8.getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_10(Variable vp_221, PointerDereferenceExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vp_221
}

predicate func_11(Variable vp_221, Variable vq_221, RelationalOperation target_11) {
		 (target_11 instanceof GTExpr or target_11 instanceof LTExpr)
		and target_11.getLesserOperand().(VariableAccess).getTarget()=vq_221
		and target_11.getGreaterOperand().(VariableAccess).getTarget()=vp_221
}

predicate func_12(Parameter vhp_218, ArrayExpr target_12) {
		target_12.getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_12.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_218
		and target_12.getArrayOffset() instanceof ArrayExpr
}

predicate func_13(Variable vp_221, PointerDereferenceExpr target_13) {
		target_13.getOperand().(VariableAccess).getTarget()=vp_221
}

predicate func_14(Variable vq_221, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vq_221
		and target_14.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

predicate func_15(Variable vp_221, LogicalAndExpr target_15) {
		target_15.getAnOperand().(FunctionCall).getTarget().hasName("vct_is")
		and target_15.getAnOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_221
		and target_15.getAnOperand().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="4"
		and target_15.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("vct_is")
		and target_15.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_221
		and target_15.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="1"
}

from Function func, Parameter vhf_218, Variable vp_221, Variable vq_221, Parameter vhp_218, VariableAccess target_0, ReturnStmt target_5, ExprStmt target_6, AssignExpr target_7, ArrayExpr target_8, PointerDereferenceExpr target_10, RelationalOperation target_11, ArrayExpr target_12, PointerDereferenceExpr target_13, ExprStmt target_14, LogicalAndExpr target_15
where
func_0(vhf_218, vp_221, vhp_218, target_8, target_10, target_11, target_12, target_0)
and not func_1(vp_221, vq_221, target_13, target_14)
and not func_2(vp_221, vq_221, target_6, func)
and func_5(target_15, func, target_5)
and func_6(vhf_218, vp_221, vhp_218, func, target_6)
and func_7(vhp_218, target_7)
and func_8(vhf_218, vhp_218, target_8)
and func_10(vp_221, target_10)
and func_11(vp_221, vq_221, target_11)
and func_12(vhp_218, target_12)
and func_13(vp_221, target_13)
and func_14(vq_221, target_14)
and func_15(vp_221, target_15)
and vhf_218.getType().hasName("const int *")
and vp_221.getType().hasName("char *")
and vq_221.getType().hasName("char *")
and vhp_218.getType().hasName("http *")
and vhf_218.getParentScope+() = func
and vp_221.getParentScope+() = func
and vq_221.getParentScope+() = func
and vhp_218.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
