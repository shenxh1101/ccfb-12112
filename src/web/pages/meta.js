/** 页面共享的状态文案（与后端 STATUS_META 对应，前端独立维护避免耦合） */
export const STATUS_LABEL = {
  'pass': '已挡住',
  'bypass': '脚本执行（绕过）',
  'clobbered': 'DOM Clobbering 成立',
  'css-exfil': 'CSS 外联外泄',
  'css-style-survive': '危险样式存活',
  'error': '检测异常'
};
