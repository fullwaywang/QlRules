/**
 * @name e2fsprogs-8dbe7b475ec5e91ed767239f0e85880f416fc384-qtree_scan_dquots
 * @id cpp/e2fsprogs/8dbe7b475ec5e91ed767239f0e85880f416fc384/qtree-scan-dquots
 * @description e2fsprogs-8dbe7b475ec5e91ed767239f0e85880f416fc384-lib/support/quotaio_tree.c-qtree_scan_dquots CVE-2019-5094
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getRValue() instanceof FunctionCall
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and target_1.getThen().(GotoStmt).getName() ="errout"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_1))
}

predicate func_2(Variable vv2info_646, AddressOfExpr target_9, ExprStmt target_10, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dqi_used_entries"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv2info_646
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_2)
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_4))
}

predicate func_5(Function func) {
	exists(LabelStmt target_5 |
		target_5.toString() = "label ...:"
		and target_5.getName() ="errout"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_5))
}

predicate func_7(Parameter vprocess_dquot_642, Parameter vdata_643, Variable vbitmap_645, Variable vdquot_648, FunctionCall target_7) {
		target_7.getTarget().hasName("report_tree")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vdquot_648
		and target_7.getArgument(1).(Literal).getValue()="1"
		and target_7.getArgument(2).(Literal).getValue()="0"
		and target_7.getArgument(3).(VariableAccess).getTarget()=vbitmap_645
		and target_7.getArgument(4).(VariableAccess).getTarget()=vprocess_dquot_642
		and target_7.getArgument(5).(VariableAccess).getTarget()=vdata_643
}

predicate func_9(Variable vv2info_646, AddressOfExpr target_9) {
		target_9.getOperand().(PointerFieldAccess).getTarget().getName()="dqi_qtree"
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv2info_646
}

predicate func_10(Variable vbitmap_645, Variable vv2info_646, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dqi_data_blocks"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv2info_646
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("find_set_bits")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbitmap_645
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dqi_blocks"
}

from Function func, Parameter vprocess_dquot_642, Parameter vdata_643, Variable vbitmap_645, Variable vv2info_646, Variable vdquot_648, FunctionCall target_7, AddressOfExpr target_9, ExprStmt target_10
where
not func_0(func)
and not func_1(func)
and not func_2(vv2info_646, target_9, target_10, func)
and not func_4(func)
and not func_5(func)
and func_7(vprocess_dquot_642, vdata_643, vbitmap_645, vdquot_648, target_7)
and func_9(vv2info_646, target_9)
and func_10(vbitmap_645, vv2info_646, target_10)
and vprocess_dquot_642.getType().hasName("..(*)(..)")
and vdata_643.getType().hasName("void *")
and vbitmap_645.getType().hasName("char *")
and vv2info_646.getType().hasName("v2_mem_dqinfo *")
and vdquot_648.getType().hasName("dquot *")
and vprocess_dquot_642.getParentScope+() = func
and vdata_643.getParentScope+() = func
and vbitmap_645.getParentScope+() = func
and vv2info_646.getParentScope+() = func
and vdquot_648.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
