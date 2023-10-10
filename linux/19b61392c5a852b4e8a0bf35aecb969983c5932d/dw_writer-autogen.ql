/**
 * @name linux-19b61392c5a852b4e8a0bf35aecb969983c5932d-dw_writer
 * @id cpp/linux/19b61392c5a852b4e8a0bf35aecb969983c5932d/dw-writer
 * @description linux-19b61392c5a852b4e8a0bf35aecb969983c5932d-dw_writer 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdws_173, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("spin_lock")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buf_lock"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdws_173
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Variable vmax_175, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_175
		and target_1.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vdws_173, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buf_lock"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdws_173
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vdws_173) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("tx_max")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vdws_173)
}

predicate func_4(Function func) {
	exists(Initializer target_4 |
		target_4.getExpr() instanceof FunctionCall
		and target_4.getExpr().getEnclosingFunction() = func)
}

predicate func_6(Parameter vdws_173) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="n_bytes"
		and target_6.getQualifier().(VariableAccess).getTarget()=vdws_173)
}

from Function func, Parameter vdws_173, Variable vmax_175
where
not func_0(vdws_173, func)
and not func_1(vmax_175, func)
and not func_2(vdws_173, func)
and func_3(vdws_173)
and func_4(func)
and vdws_173.getType().hasName("dw_spi *")
and func_6(vdws_173)
and vmax_175.getType().hasName("u32")
and vdws_173.getParentScope+() = func
and vmax_175.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
