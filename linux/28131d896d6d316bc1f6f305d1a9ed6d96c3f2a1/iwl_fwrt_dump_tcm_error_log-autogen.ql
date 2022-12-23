/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fwrt_dump_tcm_error_log
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-fwrt-dump-tcm-error-log
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fwrt_dump_tcm_error_log CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_18(Parameter vfwrt_298, Variable vtrans_300, Function func) {
	exists(IfStmt target_18 |
		target_18.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="device_family"
		and target_18.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trans_cfg"
		and target_18.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_300
		and target_18.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getTarget().hasName("iwl_read32")
		and target_18.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_300
		and target_18.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="0"
		and target_18.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="44"
		and target_18.getThen().(BlockStmt).getStmt(1).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_18.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_18.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(FunctionDeclarationEntry).getType() instanceof VoidType
		and target_18.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(StringLiteral).getValue()="Function Scratch status:\n"
		and target_18.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Function Scratch status:\n"
		and target_18.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_18.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_18.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__compiletime_assert_1739")
		and target_18.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__iwl_err")
		and target_18.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dev"
		and target_18.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_298
		and target_18.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Function Scratch status:\n"
		and target_18.getThen().(BlockStmt).getStmt(2).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_18.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_18.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(FunctionDeclarationEntry).getType() instanceof VoidType
		and target_18.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(StringLiteral).getValue()="0x%08X | Func Scratch\n"
		and target_18.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="0x%08X | Func Scratch\n"
		and target_18.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_18.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_18.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__compiletime_assert_1740")
		and target_18.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__iwl_err")
		and target_18.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dev"
		and target_18.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_298
		and target_18.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="0x%08X | Func Scratch\n"
		and target_18.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("u32")
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_18 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_18))
}

predicate func_42(Parameter vfwrt_298) {
	exists(PointerFieldAccess target_42 |
		target_42.getTarget().getName()="dev"
		and target_42.getQualifier().(VariableAccess).getTarget()=vfwrt_298)
}

predicate func_43(Variable vtrans_300, Variable vtable_301, Variable vbase_302) {
	exists(FunctionCall target_43 |
		target_43.getTarget().hasName("iwl_trans_read_mem")
		and target_43.getArgument(0).(VariableAccess).getTarget()=vtrans_300
		and target_43.getArgument(1).(VariableAccess).getTarget()=vbase_302
		and target_43.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtable_301
		and target_43.getArgument(3).(DivExpr).getValue()="23"
		and target_43.getArgument(3).(DivExpr).getLeftOperand().(SizeofExprOperator).getValue()="92"
		and target_43.getArgument(3).(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vtable_301
		and target_43.getArgument(3).(DivExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_43.getArgument(3).(DivExpr).getRightOperand().(SizeofTypeOperator).getValue()="4")
}

from Function func, Parameter vfwrt_298, Variable vtrans_300, Variable vtable_301, Variable vbase_302
where
not func_18(vfwrt_298, vtrans_300, func)
and vfwrt_298.getType().hasName("iwl_fw_runtime *")
and func_42(vfwrt_298)
and vtrans_300.getType().hasName("iwl_trans *")
and func_43(vtrans_300, vtable_301, vbase_302)
and vtable_301.getType().hasName("iwl_tcm_error_event_table")
and vbase_302.getType().hasName("u32")
and vfwrt_298.getParentScope+() = func
and vtrans_300.getParentScope+() = func
and vtable_301.getParentScope+() = func
and vbase_302.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
