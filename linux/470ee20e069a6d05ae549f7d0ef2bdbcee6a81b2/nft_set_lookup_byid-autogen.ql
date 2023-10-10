/**
 * @name linux-470ee20e069a6d05ae549f7d0ef2bdbcee6a81b2-nft_set_lookup_byid
 * @id cpp/linux/470ee20e069a6d05ae549f7d0ef2bdbcee6a81b2/nft_set_lookup_byid
 * @description linux-470ee20e069a6d05ae549f7d0ef2bdbcee6a81b2-nft_set_lookup_byid CVE-2022-2586
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vset_3853, Parameter vgenmask_3845) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="table"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vset_3853
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("const nft_table *")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="genmask"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vset_3853
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(VariableAccess).getTarget()=vgenmask_3845
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vset_3853)
}

predicate func_1(Variable vtrans_3849, Variable vset_3853, Parameter vgenmask_3845, Variable vid_3848) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vid_3848
		and target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="set_id"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_3849
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="genmask"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vset_3853
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(VariableAccess).getTarget()=vgenmask_3845
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vset_3853)
}

from Function func, Variable vtrans_3849, Variable vset_3853, Parameter vgenmask_3845, Variable vid_3848
where
not func_0(vset_3853, vgenmask_3845)
and func_1(vtrans_3849, vset_3853, vgenmask_3845, vid_3848)
and vtrans_3849.getType().hasName("nft_trans *")
and vset_3853.getType().hasName("nft_set *")
and vgenmask_3845.getType().hasName("u8")
and vid_3848.getType().hasName("u32")
and vtrans_3849.getParentScope+() = func
and vset_3853.getParentScope+() = func
and vgenmask_3845.getParentScope+() = func
and vid_3848.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
