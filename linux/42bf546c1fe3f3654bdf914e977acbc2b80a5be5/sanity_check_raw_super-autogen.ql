/**
 * @name linux-42bf546c1fe3f3654bdf914e977acbc2b80a5be5-sanity_check_raw_super
 * @id cpp/linux/42bf546c1fe3f3654bdf914e977acbc2b80a5be5/sanity_check_raw_super
 * @description linux-42bf546c1fe3f3654bdf914e977acbc2b80a5be5-sanity_check_raw_super 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="Wrong secs_per_zone (%u > %u)"
		and not target_0.getValue()="Wrong secs_per_zone / total_sections (%u, %u)"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vsecs_per_zone_2133, Variable vtotal_sections_2134, Variable vsb_2137) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand() instanceof RelationalOperation
		and target_1.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vsecs_per_zone_2133
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("f2fs_msg")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2137
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="6"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Wrong secs_per_zone / total_sections (%u, %u)"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vsecs_per_zone_2133
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vtotal_sections_2134
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1")
}

predicate func_2(Variable vsecs_per_zone_2133, Variable vtotal_sections_2134, Variable vsb_2137) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vsecs_per_zone_2133
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vtotal_sections_2134
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("f2fs_msg")
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2137
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="6"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vsecs_per_zone_2133
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vtotal_sections_2134
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1")
}

predicate func_3(Variable vsecs_per_zone_2133, Variable vraw_super_2135) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vsecs_per_zone_2133
		and target_3.getRValue().(PointerFieldAccess).getTarget().getName()="secs_per_zone"
		and target_3.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vraw_super_2135)
}

from Function func, Variable vsecs_per_zone_2133, Variable vtotal_sections_2134, Variable vraw_super_2135, Variable vsb_2137
where
func_0(func)
and not func_1(vsecs_per_zone_2133, vtotal_sections_2134, vsb_2137)
and func_2(vsecs_per_zone_2133, vtotal_sections_2134, vsb_2137)
and vsecs_per_zone_2133.getType().hasName("block_t")
and func_3(vsecs_per_zone_2133, vraw_super_2135)
and vtotal_sections_2134.getType().hasName("block_t")
and vraw_super_2135.getType().hasName("f2fs_super_block *")
and vsb_2137.getType().hasName("super_block *")
and vsecs_per_zone_2133.getParentScope+() = func
and vtotal_sections_2134.getParentScope+() = func
and vraw_super_2135.getParentScope+() = func
and vsb_2137.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
