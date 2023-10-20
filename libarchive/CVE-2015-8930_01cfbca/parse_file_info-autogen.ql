/**
 * @name libarchive-01cfbca4fdae1492a8a09c001b61bbca46f869f2-parse_file_info
 * @id cpp/libarchive/01cfbca4fdae1492a8a09c001b61bbca46f869f2/parse-file-info
 * @description libarchive-01cfbca4fdae1492a8a09c001b61bbca46f869f2-libarchive/archive_read_support_format_iso9660.c-parse_file_info CVE-2015-8930
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_3(Parameter vparent_1751, ExprStmt target_6, Function func) {
	exists(ForStmt target_3 |
		target_3.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("file_info *")
		and target_3.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vparent_1751
		and target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("file_info *")
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getUpdate().(AssignExpr).getLValue().(VariableAccess).getType().hasName("file_info *")
		and target_3.getUpdate().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="parent"
		and target_3.getUpdate().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("file_info *")
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="offset"
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("file_info *")
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="84"
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Directory structure contains loop"
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_3)
		and target_3.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_4(Variable vfile_1755, ExprStmt target_6, ExprStmt target_7, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="offset"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfile_1755
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("uint64_t")
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_4)
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Variable vfile_1755, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="offset"
		and target_5.getQualifier().(VariableAccess).getTarget()=vfile_1755
		and target_5.getParent().(AssignExpr).getLValue() = target_5
		and target_5.getParent().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="logical_block_size"
}

predicate func_6(Parameter vparent_1751, Variable vfile_1755, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="parent"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfile_1755
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vparent_1751
}

predicate func_7(Variable vfile_1755, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfile_1755
}

from Function func, Parameter vparent_1751, Variable vfile_1755, PointerFieldAccess target_5, ExprStmt target_6, ExprStmt target_7
where
not func_3(vparent_1751, target_6, func)
and not func_4(vfile_1755, target_6, target_7, func)
and func_5(vfile_1755, target_5)
and func_6(vparent_1751, vfile_1755, target_6)
and func_7(vfile_1755, target_7)
and vparent_1751.getType().hasName("file_info *")
and vfile_1755.getType().hasName("file_info *")
and vparent_1751.getParentScope+() = func
and vfile_1755.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
