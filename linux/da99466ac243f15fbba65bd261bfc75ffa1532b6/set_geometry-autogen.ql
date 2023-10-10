/**
 * @name linux-da99466ac243f15fbba65bd261bfc75ffa1532b6-set_geometry
 * @id cpp/linux/da99466ac243f15fbba65bd261bfc75ffa1532b6/set_geometry
 * @description linux-da99466ac243f15fbba65bd261bfc75ffa1532b6-set_geometry 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vg_3230) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="sect"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_3230
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="head"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_3230
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_1(Parameter vg_3230) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="sect"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_3230
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="head"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_3230
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

from Function func, Parameter vg_3230
where
not func_0(vg_3230)
and func_1(vg_3230)
and vg_3230.getType().hasName("floppy_struct *")
and vg_3230.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
