/**
 * @name linux-979d63d50c0c0f7bc537bf821e056cc9fe5abd38-adjust_ptr_min_max_vals
 * @id cpp/linux/979d63d50c0c0f7bc537bf821e056cc9fe5abd38/adjust_ptr_min_max_vals
 * @description linux-979d63d50c0c0f7bc537bf821e056cc9fe5abd38-adjust_ptr_min_max_vals 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		func.getEntryPoint().(BlockStmt).getStmt(8)=target_0)
}

predicate func_1(Parameter venv_3075, Parameter vinsn_3076, Parameter vptr_reg_3077, Variable vdst_reg_3082, Variable vsmin_val_3084) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sanitize_ptr_alu")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=venv_3075
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinsn_3076
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vptr_reg_3077
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdst_reg_3082
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsmin_val_3084
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_2(Parameter venv_3075, Variable vdst_3088) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("verbose")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=venv_3075
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="R%d tried to add from different maps or paths\n"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdst_3088
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getType().hasName("int"))
}

predicate func_6(Parameter venv_3075, Variable vdst_3088) {
	exists(IfStmt target_6 |
		target_6.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("verbose")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=venv_3075
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="R%d tried to sub from different maps or paths\n"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdst_3088
		and target_6.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getType().hasName("int"))
}

predicate func_9(Parameter venv_3075, Parameter vptr_reg_3077) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("check_reg_sane_offset")
		and target_9.getArgument(0).(VariableAccess).getTarget()=venv_3075
		and target_9.getArgument(1).(VariableAccess).getTarget()=vptr_reg_3077
		and target_9.getArgument(2).(PointerFieldAccess).getTarget().getName()="type"
		and target_9.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vptr_reg_3077)
}

predicate func_10(Parameter venv_3075) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="id_gen"
		and target_10.getQualifier().(VariableAccess).getTarget()=venv_3075)
}

predicate func_11(Parameter vinsn_3076) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="code"
		and target_11.getQualifier().(VariableAccess).getTarget()=vinsn_3076)
}

predicate func_12(Parameter vptr_reg_3077) {
	exists(PointerFieldAccess target_12 |
		target_12.getTarget().getName()="type"
		and target_12.getQualifier().(VariableAccess).getTarget()=vptr_reg_3077)
}

predicate func_13(Parameter vptr_reg_3077) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("reg_is_pkt_pointer")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vptr_reg_3077)
}

predicate func_14(Variable vdst_reg_3082) {
	exists(PointerFieldAccess target_14 |
		target_14.getTarget().getName()="id"
		and target_14.getQualifier().(VariableAccess).getTarget()=vdst_reg_3082)
}

predicate func_15(Variable vdst_reg_3082) {
	exists(PointerFieldAccess target_15 |
		target_15.getTarget().getName()="(unknown field)"
		and target_15.getQualifier().(VariableAccess).getTarget()=vdst_reg_3082)
}

predicate func_16(Variable vsmin_val_3084) {
	exists(RelationalOperation target_16 |
		 (target_16 instanceof GTExpr or target_16 instanceof LTExpr)
		and target_16.getLesserOperand().(VariableAccess).getTarget()=vsmin_val_3084
		and target_16.getGreaterOperand().(Literal).getValue()="0")
}

predicate func_17(Variable vdst_reg_3082, Variable vsmin_val_3084, Variable vsmin_ptr_3085) {
	exists(AddExpr target_17 |
		target_17.getAnOperand().(VariableAccess).getTarget()=vsmin_ptr_3085
		and target_17.getAnOperand().(VariableAccess).getTarget()=vsmin_val_3084
		and target_17.getParent().(AssignExpr).getRValue() = target_17
		and target_17.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="smin_value"
		and target_17.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_reg_3082)
}

predicate func_18(Parameter venv_3075, Parameter voff_reg_3078, Variable vdst_reg_3082, Variable vdst_3088, Variable vsrc_3088) {
	exists(ConditionalExpr target_18 |
		target_18.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=voff_reg_3078
		and target_18.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdst_reg_3082
		and target_18.getThen().(VariableAccess).getTarget()=vdst_3088
		and target_18.getElse().(VariableAccess).getTarget()=vsrc_3088
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("verbose")
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=venv_3075
		and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="R%d has unknown scalar with mixed signed bounds, pointer arithmetic with it prohibited for !root\n")
}

from Function func, Parameter venv_3075, Parameter vinsn_3076, Parameter vptr_reg_3077, Parameter voff_reg_3078, Variable vdst_reg_3082, Variable vsmin_val_3084, Variable vsmin_ptr_3085, Variable vdst_3088, Variable vsrc_3088
where
not func_0(func)
and not func_1(venv_3075, vinsn_3076, vptr_reg_3077, vdst_reg_3082, vsmin_val_3084)
and not func_2(venv_3075, vdst_3088)
and not func_6(venv_3075, vdst_3088)
and venv_3075.getType().hasName("bpf_verifier_env *")
and func_9(venv_3075, vptr_reg_3077)
and func_10(venv_3075)
and vinsn_3076.getType().hasName("bpf_insn *")
and func_11(vinsn_3076)
and vptr_reg_3077.getType().hasName("const bpf_reg_state *")
and func_12(vptr_reg_3077)
and func_13(vptr_reg_3077)
and vdst_reg_3082.getType().hasName("bpf_reg_state *")
and func_14(vdst_reg_3082)
and func_15(vdst_reg_3082)
and vsmin_val_3084.getType().hasName("s64")
and func_16(vsmin_val_3084)
and func_17(vdst_reg_3082, vsmin_val_3084, vsmin_ptr_3085)
and vsmin_ptr_3085.getType().hasName("s64")
and vdst_3088.getType().hasName("u32")
and func_18(venv_3075, voff_reg_3078, vdst_reg_3082, vdst_3088, vsrc_3088)
and vsrc_3088.getType().hasName("u32")
and venv_3075.getParentScope+() = func
and vinsn_3076.getParentScope+() = func
and vptr_reg_3077.getParentScope+() = func
and voff_reg_3078.getParentScope+() = func
and vdst_reg_3082.getParentScope+() = func
and vsmin_val_3084.getParentScope+() = func
and vsmin_ptr_3085.getParentScope+() = func
and vdst_3088.getParentScope+() = func
and vsrc_3088.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
