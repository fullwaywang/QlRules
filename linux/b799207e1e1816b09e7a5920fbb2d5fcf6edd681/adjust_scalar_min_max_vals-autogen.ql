/**
 * @name linux-b799207e1e1816b09e7a5920fbb2d5fcf6edd681-adjust_scalar_min_max_vals
 * @id cpp/linux/b799207e1e1816b09e7a5920fbb2d5fcf6edd681/adjust_scalar_min_max_vals
 * @description linux-b799207e1e1816b09e7a5920fbb2d5fcf6edd681-adjust_scalar_min_max_vals 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vdst_reg_2889, Parameter vsrc_reg_2890, Variable vinsn_bitness_2897) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vinsn_bitness_2897
		and target_0.getAnOperand().(Literal).getValue()="32"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("coerce_reg_to_size")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdst_reg_2889
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("coerce_reg_to_size")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsrc_reg_2890
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4")
}

predicate func_1(Parameter vdst_reg_2889, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition() instanceof EqualityOperation
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("coerce_reg_to_size")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdst_reg_2889
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_1))
}

predicate func_3(Parameter vinsn_2888, Parameter vdst_reg_2889, Parameter vsrc_reg_2890) {
	exists(EqualityOperation target_3 |
		target_3.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="code"
		and target_3.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinsn_2888
		and target_3.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="7"
		and target_3.getAnOperand().(Literal).getValue()="7"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("coerce_reg_to_size")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdst_reg_2889
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("coerce_reg_to_size")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsrc_reg_2890
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4")
}

predicate func_4(Parameter vdst_reg_2889) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("coerce_reg_to_size")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vdst_reg_2889
		and target_4.getArgument(1).(Literal).getValue()="4")
}

predicate func_5(Parameter venv_2887, Parameter vinsn_2888, Variable vregs_2892, Variable vumax_val_2896, Variable vinsn_bitness_2897) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GEExpr or target_5 instanceof LEExpr)
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vumax_val_2896
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vinsn_bitness_2897
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mark_reg_unknown")
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=venv_2887
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vregs_2892
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="dst_reg"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinsn_2888
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;")
}

from Function func, Parameter venv_2887, Parameter vinsn_2888, Parameter vdst_reg_2889, Parameter vsrc_reg_2890, Variable vregs_2892, Variable vumax_val_2896, Variable vinsn_bitness_2897
where
not func_0(vdst_reg_2889, vsrc_reg_2890, vinsn_bitness_2897)
and not func_1(vdst_reg_2889, func)
and func_3(vinsn_2888, vdst_reg_2889, vsrc_reg_2890)
and vinsn_2888.getType().hasName("bpf_insn *")
and vdst_reg_2889.getType().hasName("bpf_reg_state *")
and func_4(vdst_reg_2889)
and vsrc_reg_2890.getType().hasName("bpf_reg_state")
and vinsn_bitness_2897.getType().hasName("u64")
and func_5(venv_2887, vinsn_2888, vregs_2892, vumax_val_2896, vinsn_bitness_2897)
and venv_2887.getParentScope+() = func
and vinsn_2888.getParentScope+() = func
and vdst_reg_2889.getParentScope+() = func
and vsrc_reg_2890.getParentScope+() = func
and vregs_2892.getParentScope+() = func
and vumax_val_2896.getParentScope+() = func
and vinsn_bitness_2897.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
