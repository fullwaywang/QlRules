/**
 * @name libsndfile-aaea680337267bfb6d2544da878890ee7f1c5077-main
 * @id cpp/libsndfile/aaea680337267bfb6d2544da878890ee7f1c5077/main
 * @description libsndfile-aaea680337267bfb6d2544da878890ee7f1c5077-programs/sndfile-deinterleave.c-main CVE-2018-13139
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vargv_67, Variable vsfinfo_69, ArrayExpr target_2, ArrayExpr target_3, RelationalOperation target_4, ExprStmt target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="channels"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsfinfo_69
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printf")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="\nError : Input file '%s' has too many (%d) channels. Limit is %d.\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargv_67
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="channels"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsfinfo_69
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0)
		and target_2.getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_3.getArrayBase().(VariableAccess).getLocation())
		and target_4.getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vargv_67, ArrayExpr target_2) {
		target_2.getArrayBase().(VariableAccess).getTarget()=vargv_67
		and target_2.getArrayOffset().(Literal).getValue()="1"
}

predicate func_3(Parameter vargv_67, ArrayExpr target_3) {
		target_3.getArrayBase().(VariableAccess).getTarget()=vargv_67
		and target_3.getArrayOffset().(Literal).getValue()="1"
}

predicate func_4(Variable vsfinfo_69, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(ValueFieldAccess).getTarget().getName()="channels"
		and target_4.getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsfinfo_69
		and target_4.getGreaterOperand().(Literal).getValue()="2"
}

predicate func_5(Variable vsfinfo_69, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="channels"
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="channels"
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsfinfo_69
}

from Function func, Parameter vargv_67, Variable vsfinfo_69, ArrayExpr target_2, ArrayExpr target_3, RelationalOperation target_4, ExprStmt target_5
where
not func_0(vargv_67, vsfinfo_69, target_2, target_3, target_4, target_5, func)
and func_2(vargv_67, target_2)
and func_3(vargv_67, target_3)
and func_4(vsfinfo_69, target_4)
and func_5(vsfinfo_69, target_5)
and vargv_67.getType().hasName("char **")
and vsfinfo_69.getType().hasName("SF_INFO")
and vargv_67.getParentScope+() = func
and vsfinfo_69.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
