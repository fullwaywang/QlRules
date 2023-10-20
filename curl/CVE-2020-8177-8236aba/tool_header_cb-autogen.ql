/**
 * @name curl-8236aba58542c5f-tool_header_cb
 * @id cpp/curl/8236aba58542c5f/tool-header-cb
 * @description curl-8236aba58542c5f-tool_header_cb CVE-2020-8177
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vouts_60) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="stream"
		and target_0.getQualifier().(VariableAccess).getTarget()=vouts_60
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_1(Variable vper_58) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="config"
		and target_1.getQualifier().(VariableAccess).getTarget()=vper_58)
}

predicate func_2(Variable vouts_60) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="filename"
		and target_2.getQualifier().(VariableAccess).getTarget()=vouts_60
		and target_2.getParent().(AssignExpr).getLValue() = target_2
		and target_2.getParent().(AssignExpr).getRValue() instanceof Literal)
}

predicate func_3(Variable vouts_60) {
	exists(DeclStmt target_3 |
		target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="stream"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vouts_60)
}

predicate func_4(Variable vouts_60) {
	exists(IfStmt target_4 |
		target_4.getCondition().(PointerFieldAccess).getTarget().getName()="fopened"
		and target_4.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vouts_60
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof PointerFieldAccess
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="stream"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vouts_60)
}

predicate func_5(Variable vouts_60) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="stream"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vouts_60
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="stream"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vouts_60)
}

predicate func_6(Variable vouts_60, Variable vfilename_166, Variable vrc_189) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_189
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("rename")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="filename"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vouts_60
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfilename_166
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="stream"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vouts_60)
}

predicate func_7(Variable vouts_60, Variable vfilename_166, Variable vrc_189) {
	exists(IfStmt target_7 |
		target_7.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrc_189
		and target_7.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("warnf")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="global"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to rename %s -> %s: %s\n"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="filename"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vouts_60
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vfilename_166
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("strerror")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="stream"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vouts_60)
}

predicate func_9(Variable vouts_60) {
	exists(IfStmt target_9 |
		target_9.getCondition().(PointerFieldAccess).getTarget().getName()="alloc_filename"
		and target_9.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vouts_60
		and target_9.getThen().(DoStmt).getCondition().(Literal).getValue()="0"
		and target_9.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_9.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="filename"
		and target_9.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vouts_60
		and target_9.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue() instanceof PointerFieldAccess
		and target_9.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="stream"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vouts_60)
}

predicate func_12(Variable vfailure_74, Variable vouts_60, Variable vfilename_166, Variable vrc_189) {
	exists(IfStmt target_12 |
		target_12.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrc_189
		and target_12.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfilename_166
		and target_12.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vfailure_74
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="stream"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vouts_60)
}

from Function func, Variable vfailure_74, Variable vper_58, Variable vouts_60, Variable vfilename_166, Variable vrc_189
where
func_0(vouts_60)
and func_1(vper_58)
and func_2(vouts_60)
and func_3(vouts_60)
and func_4(vouts_60)
and func_5(vouts_60)
and func_6(vouts_60, vfilename_166, vrc_189)
and func_7(vouts_60, vfilename_166, vrc_189)
and func_9(vouts_60)
and func_12(vfailure_74, vouts_60, vfilename_166, vrc_189)
and vfailure_74.getType().hasName("size_t")
and vper_58.getType().hasName("per_transfer *")
and vouts_60.getType().hasName("OutStruct *")
and vfilename_166.getType().hasName("char *")
and vrc_189.getType().hasName("int")
and vfailure_74.getParentScope+() = func
and vper_58.getParentScope+() = func
and vouts_60.getParentScope+() = func
and vfilename_166.getParentScope+() = func
and vrc_189.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
