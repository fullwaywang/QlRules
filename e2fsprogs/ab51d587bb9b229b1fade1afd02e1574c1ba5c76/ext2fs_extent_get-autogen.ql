/**
 * @name e2fsprogs-ab51d587bb9b229b1fade1afd02e1574c1ba5c76-ext2fs_extent_get
 * @id cpp/e2fsprogs/ab51d587bb9b229b1fade1afd02e1574c1ba5c76/ext2fs-extent-get
 * @description e2fsprogs-ab51d587bb9b229b1fade1afd02e1574c1ba5c76-lib/ext2fs/extent.c-ext2fs_extent_get CVE-2022-1304
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnewpath_308, VariableAccess target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="left"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewpath_308
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="2133571455"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vop_315, VariableAccess target_1) {
		target_1.getTarget()=vop_315
}

predicate func_2(Variable vnewpath_308, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="max_entries"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewpath_308
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="eh_max"
}

predicate func_3(Variable vnewpath_308, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="end_blk"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewpath_308
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="ei_block"
}

from Function func, Variable vnewpath_308, Variable vop_315, VariableAccess target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vnewpath_308, target_1, target_2, target_3)
and func_1(vop_315, target_1)
and func_2(vnewpath_308, target_2)
and func_3(vnewpath_308, target_3)
and vnewpath_308.getType().hasName("extent_path *")
and vop_315.getType().hasName("int")
and vnewpath_308.getParentScope+() = func
and vop_315.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
