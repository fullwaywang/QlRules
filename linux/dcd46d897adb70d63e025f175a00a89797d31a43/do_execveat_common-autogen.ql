/**
 * @name linux-dcd46d897adb70d63e025f175a00a89797d31a43-do_execveat_common
 * @id cpp/linux/dcd46d897adb70d63e025f175a00a89797d31a43/do-execveat-common
 * @description linux-dcd46d897adb70d63e025f175a00a89797d31a43-do_execveat_common CVE-2021-4034
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbprm_1871, Variable vretval_1872, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vretval_1872
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getType().hasName("bool")
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("bool")
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("bool")
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof Literal
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof Literal
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ClassAggregateLiteral).getValue()="{...}"
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("const pi_entry")
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_printk")
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="4process '%s' launched '%s' with NULL argv: empty string added\n"
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="comm"
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("get_current")
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="filename"
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbprm_1871
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("bool")
		and target_0.getThen().(ExprStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and func.getEntryPoint().(BlockStmt).getStmt(8)=target_0)
}

predicate func_12(Variable vbprm_1871, Variable vretval_1872, Function func) {
	exists(IfStmt target_12 |
		target_12.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="argc"
		and target_12.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbprm_1871
		and target_12.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_1872
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("copy_string_kernel")
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StringLiteral).getValue()=""
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbprm_1871
		and target_12.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vretval_1872
		and target_12.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_12.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_12.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="argc"
		and target_12.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbprm_1871
		and target_12.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getStmt(23)=target_12)
}

predicate func_16(Variable vbprm_1871) {
	exists(FunctionCall target_16 |
		target_16.getTarget().hasName("PTR_ERR")
		and target_16.getArgument(0).(VariableAccess).getTarget()=vbprm_1871)
}

predicate func_17(Parameter vargv_1867, Variable vbprm_1871) {
	exists(FunctionCall target_17 |
		target_17.getTarget().hasName("copy_strings")
		and target_17.getArgument(0).(PointerFieldAccess).getTarget().getName()="argc"
		and target_17.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbprm_1871
		and target_17.getArgument(1).(VariableAccess).getTarget()=vargv_1867
		and target_17.getArgument(2).(VariableAccess).getTarget()=vbprm_1871)
}

predicate func_18(Parameter vargv_1867, Variable vretval_1872) {
	exists(AssignExpr target_18 |
		target_18.getLValue().(VariableAccess).getTarget()=vretval_1872
		and target_18.getRValue().(FunctionCall).getTarget().hasName("count")
		and target_18.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vargv_1867
		and target_18.getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="2147483647")
}

from Function func, Parameter vargv_1867, Variable vbprm_1871, Variable vretval_1872
where
not func_0(vbprm_1871, vretval_1872, func)
and not func_12(vbprm_1871, vretval_1872, func)
and vbprm_1871.getType().hasName("linux_binprm *")
and func_16(vbprm_1871)
and func_17(vargv_1867, vbprm_1871)
and vretval_1872.getType().hasName("int")
and func_18(vargv_1867, vretval_1872)
and vargv_1867.getParentScope+() = func
and vbprm_1871.getParentScope+() = func
and vretval_1872.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
