/**
 * @name libwebp-eb82ce76ddca13ad6fb13376bb58b9fd3f850e9e-MuxImageParse
 * @id cpp/libwebp/eb82ce76ddca13ad6fb13376bb58b9fd3f850e9e/MuxImageParse
 * @description libwebp-eb82ce76ddca13ad6fb13376bb58b9fd3f850e9e-src/mux/muxread.c-MuxImageParse CVE-2018-25011
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vwpi_100, FunctionCall target_1, ExprStmt target_2, AddressOfExpr target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="img_"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpi_100
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(GotoStmt).getName() ="Fail"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(FunctionCall target_1) {
		target_1.getTarget().hasName("ChunkGetIdFromTag")
		and target_1.getArgument(0).(ValueFieldAccess).getTarget().getName()="tag_"
}

predicate func_2(Parameter vwpi_100, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_partial_"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpi_100
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_3(Parameter vwpi_100, AddressOfExpr target_3) {
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="img_"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpi_100
}

from Function func, Parameter vwpi_100, FunctionCall target_1, ExprStmt target_2, AddressOfExpr target_3
where
not func_0(vwpi_100, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vwpi_100, target_2)
and func_3(vwpi_100, target_3)
and vwpi_100.getType().hasName("WebPMuxImage *const")
and vwpi_100.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
