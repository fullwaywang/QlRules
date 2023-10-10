/**
 * @name ghostscript-fb713b3818b52d8a6cf62c951eba2e1795ff9624-gs_call_interp
 * @id cpp/ghostscript/fb713b3818b52d8a6cf62c951eba2e1795ff9624/gs-call-interp
 * @description ghostscript-fb713b3818b52d8a6cf62c951eba2e1795ff9624-psi/interp.c-gs_call_interp CVE-2018-17183
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vperrordict_488, Variable vcode_490, Variable vi_ctx_p_492, AddressOfExpr target_2, ReturnStmt target_3, ReturnStmt target_4, RelationalOperation target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="LockFilePermissions"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_492
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("dict_find_string")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="gserrordict"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("dict_find")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vperrordict_488
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vcode_490
		and target_0.getElse().(BlockStmt).getStmt(0) instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_0)
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getLocation().isBefore(target_4.getExpr().(VariableAccess).getLocation())
		and target_5.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vepref_486, Variable vperrordict_488, Variable verror_name_489, Variable vcode_490, Function func, IfStmt target_1) {
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("dict_find_string")
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="system_dict"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dict_stack"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="errordict"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vperrordict_488
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("dict_find")
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vperrordict_488
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=verror_name_489
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vepref_486
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("dict_find_string")
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="gserrordict"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("dict_find")
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vperrordict_488
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vcode_490
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vperrordict_488, AddressOfExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vperrordict_488
}

predicate func_3(Variable vcode_490, ReturnStmt target_3) {
		target_3.getExpr().(VariableAccess).getTarget()=vcode_490
}

predicate func_4(Variable vcode_490, ReturnStmt target_4) {
		target_4.getExpr().(VariableAccess).getTarget()=vcode_490
}

predicate func_5(Variable verror_name_489, Variable vcode_490, Variable vi_ctx_p_492, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(FunctionCall).getTarget().hasName("gs_errorname")
		and target_5.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_492
		and target_5.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcode_490
		and target_5.getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=verror_name_489
		and target_5.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Variable vepref_486, Variable vperrordict_488, Variable verror_name_489, Variable vcode_490, Variable vi_ctx_p_492, IfStmt target_1, AddressOfExpr target_2, ReturnStmt target_3, ReturnStmt target_4, RelationalOperation target_5
where
not func_0(vperrordict_488, vcode_490, vi_ctx_p_492, target_2, target_3, target_4, target_5, func)
and func_1(vepref_486, vperrordict_488, verror_name_489, vcode_490, func, target_1)
and func_2(vperrordict_488, target_2)
and func_3(vcode_490, target_3)
and func_4(vcode_490, target_4)
and func_5(verror_name_489, vcode_490, vi_ctx_p_492, target_5)
and vepref_486.getType().hasName("ref *")
and vperrordict_488.getType().hasName("ref *")
and verror_name_489.getType().hasName("ref")
and vcode_490.getType().hasName("int")
and vi_ctx_p_492.getType().hasName("i_ctx_t *")
and vepref_486.(LocalVariable).getFunction() = func
and vperrordict_488.(LocalVariable).getFunction() = func
and verror_name_489.(LocalVariable).getFunction() = func
and vcode_490.(LocalVariable).getFunction() = func
and vi_ctx_p_492.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
