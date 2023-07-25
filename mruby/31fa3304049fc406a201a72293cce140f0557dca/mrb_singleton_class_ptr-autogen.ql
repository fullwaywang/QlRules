/**
 * @name nghttp2-31fa3304049fc406a201a72293cce140f0557dca-mrb_singleton_class_ptr
 * @id cpp/nghttp2/31fa3304049fc406a201a72293cce140f0557dca/mrb-singleton-class-ptr
 * @description nghttp2-31fa3304049fc406a201a72293cce140f0557dca-src/class.c-mrb_singleton_class_ptr CVE-2022-0240
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vobj_1665, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="c"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobj_1665
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vobj_1665, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vobj_1665
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="p"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("mrb_val_union")
}

predicate func_2(Variable vobj_1665, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("prepare_singleton_class")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vobj_1665
}

from Function func, Variable vobj_1665, ExprStmt target_1, ExprStmt target_2
where
not func_0(vobj_1665, target_1, target_2, func)
and func_1(vobj_1665, target_1)
and func_2(vobj_1665, target_2)
and vobj_1665.getType().hasName("RBasic *")
and vobj_1665.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
