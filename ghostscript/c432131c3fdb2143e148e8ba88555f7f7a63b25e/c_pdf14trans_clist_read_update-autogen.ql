/**
 * @name ghostscript-c432131c3fdb2143e148e8ba88555f7f7a63b25e-c_pdf14trans_clist_read_update
 * @id cpp/ghostscript/c432131c3fdb2143e148e8ba88555f7f7a63b25e/c-pdf14trans-clist-read-update
 * @description ghostscript-c432131c3fdb2143e148e8ba88555f7f7a63b25e-base/gdevp14.c-c_pdf14trans_clist_read_update CVE-2018-16540
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp14dev_8014, EqualityOperation target_1, ExprStmt target_2, ArrayExpr target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp14dev_8014
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vp14dev_8014, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp14dev_8014
		and target_1.getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Variable vp14dev_8014, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("pdf14_ctx_free")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp14dev_8014
}

predicate func_3(Variable vp14dev_8014, ArrayExpr target_3) {
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="device_profile"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="icc_struct"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp14dev_8014
		and target_3.getArrayOffset().(Literal).getValue()="0"
}

from Function func, Variable vp14dev_8014, EqualityOperation target_1, ExprStmt target_2, ArrayExpr target_3
where
not func_0(vp14dev_8014, target_1, target_2, target_3)
and func_1(vp14dev_8014, target_1)
and func_2(vp14dev_8014, target_2)
and func_3(vp14dev_8014, target_3)
and vp14dev_8014.getType().hasName("pdf14_device *")
and vp14dev_8014.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
