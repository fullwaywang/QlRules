/**
 * @name linux-d3bd7413e0ca40b60cf60d4003246d067cafdeda-adjust_scalar_min_max_vals
 * @id cpp/linux/d3bd7413e0ca40b60cf60d4003246d067cafdeda/adjust_scalar_min_max_vals
 * @description linux-d3bd7413e0ca40b60cf60d4003246d067cafdeda-adjust_scalar_min_max_vals 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vinsn_3411, Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="dst_reg"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinsn_3411
		and func.getEntryPoint().(BlockStmt).getStmt(6)=target_0)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		func.getEntryPoint().(BlockStmt).getStmt(7)=target_1)
}

predicate func_2(Parameter venv_3410, Parameter vinsn_3411) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sanitize_val_alu")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=venv_3410
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinsn_3411)
}

predicate func_3(Parameter venv_3410) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("verbose")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=venv_3410
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="R%d tried to add from different pointers or scalars\n"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("u32")
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getType().hasName("int"))
}

predicate func_7(Parameter venv_3410) {
	exists(IfStmt target_7 |
		target_7.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("verbose")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=venv_3410
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="R%d tried to sub from different pointers or scalars\n"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("u32")
		and target_7.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getType().hasName("int"))
}

predicate func_10(Parameter venv_3410) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("cur_regs")
		and target_10.getArgument(0).(VariableAccess).getTarget()=venv_3410)
}

predicate func_11(Parameter vinsn_3411) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="code"
		and target_11.getQualifier().(VariableAccess).getTarget()=vinsn_3411)
}

from Function func, Parameter venv_3410, Parameter vinsn_3411
where
not func_0(vinsn_3411, func)
and not func_1(func)
and not func_2(venv_3410, vinsn_3411)
and not func_3(venv_3410)
and not func_7(venv_3410)
and venv_3410.getType().hasName("bpf_verifier_env *")
and func_10(venv_3410)
and vinsn_3411.getType().hasName("bpf_insn *")
and func_11(vinsn_3411)
and venv_3410.getParentScope+() = func
and vinsn_3411.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
